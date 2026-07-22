#include "gateway/core/sensorprocess.hpp"
#include "gateway/core/interprocess.hpp"
#include "gateway/core/rs232_runtime.hpp"
#include "gateway/core/modbus_runtime.hpp"
#include "gateway/core/sensor_config.hpp"
#include "spdlog/spdlog.h"
#include <array>
#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>
#include <memory>
#include <unordered_map>

namespace core::sensorprocess
{
    namespace
    {
        struct portDefinition
        {
            std::string name;
            std::string devicePath;
        };

        std::string environment_or(const char* name, const char* fallback)
        {
            const char* value = std::getenv(name);
            return value && *value ? value : fallback;
        }

        // Anomaly rules received before (or independently of) the sensor's own
        // config, keyed by "sourceType|sourceId" — applied immediately if a
        // matching runtime already exists, and re-applied here whenever that
        // runtime is (re)configured, since gateway_core keeps no other local
        // persistence for anything sensor-related.
        std::string anomaly_rules_key(const std::string& sourceType, const std::string& sourceId)
        {
            return sourceType + "|" + sourceId;
        }

        void apply_pending_anomaly_rules(
            const std::unordered_map<std::string, nlohmann::json>& pending,
            const std::string& sourceType,
            const std::string& sourceId,
            auto& runtime)
        {
            const auto it = pending.find(anomaly_rules_key(sourceType, sourceId));
            if (it == pending.end()) return;
            try
            {
                runtime.apply_anomaly_rules(it->second);
            }
            catch (const std::exception& exception)
            {
                SPDLOG_ERROR("Failed to (re)apply pending anomaly rules for {} {}: {}", sourceType, sourceId, exception.what());
            }
        }

        void apply_rs232_config(
            const module::message_protocol::messageProtocol::configMessage& message,
            std::array<rs232Runtime, 2>& runtimes,
            const std::unordered_map<std::string, nlohmann::json>& pendingAnomalyRules)
        {
            const std::array<portDefinition, 2> rs232Ports {{
                {"port_0", environment_or("GATEWAY_RS232_PORT_0_DEVICE", "/dev/ttyAMA2")},
                {"port_1", environment_or("GATEWAY_RS232_PORT_1_DEVICE", "/dev/ttyAMA3")},
            }};
            if (!message.payload.contains("rs232") || !message.payload.at("rs232").is_object())
                throw std::runtime_error("rs232Config.rs232 must be an object");
            const nlohmann::json& ports = message.payload.at("rs232");
            for (std::size_t index = 0; index < rs232Ports.size(); ++index)
            {
                const auto& definition = rs232Ports[index];
                if (!ports.contains(definition.name))
                {
                    SPDLOG_WARN("RS232 config does not contain {}; leaving current runtime unchanged", definition.name);
                    continue;
                }
                const rs232Config config = parse_rs232_port_config(
                    definition.name, definition.devicePath, ports.at(definition.name));
                runtimes[index].apply(config);
                apply_pending_anomaly_rules(pendingAnomalyRules, "rs232Sensor", definition.name, runtimes[index]);
            }
            SPDLOG_INFO("Applied RS232 config message {}", message.messageId);
        }

        void apply_rs485_config(
            const module::message_protocol::messageProtocol::configMessage& message,
            std::array<std::unique_ptr<modbusRuntime>, 2>& runtimes,
            const std::unordered_map<std::string, nlohmann::json>& pendingAnomalyRules)
        {
            if (!message.payload.contains("rs485") || !message.payload.at("rs485").is_object())
                throw std::runtime_error("rs485ModbusConfig.rs485 must be an object");
            const nlohmann::json& ports = message.payload.at("rs485");
            const std::array<portDefinition, 2> definitions {{
                {"port_2", environment_or("GATEWAY_RS485_PORT_2_DEVICE", "/dev/ttyAMA4")},
                {"port_3", environment_or("GATEWAY_RS485_PORT_3_DEVICE", "/dev/ttyAMA0")},
            }};
            for (std::size_t index = 0; index < definitions.size(); ++index)
            {
                if (!ports.contains(definitions[index].name)) continue;
                runtimes[index]->apply_rtu(parse_rs485_port_config(
                    definitions[index].name, definitions[index].devicePath, ports.at(definitions[index].name)));
                apply_pending_anomaly_rules(pendingAnomalyRules, "modbusRtu", definitions[index].name, *runtimes[index]);
            }
            SPDLOG_INFO("Applied RS485 Modbus config message {}", message.messageId);
        }

        void apply_modbus_tcp_config(
            const module::message_protocol::messageProtocol::configMessage& message,
            std::unordered_map<std::string, std::unique_ptr<modbusRuntime>>& runtimes,
            const std::unordered_map<std::string, nlohmann::json>& pendingAnomalyRules)
        {
            if (!message.payload.contains("connections") || !message.payload.at("connections").is_array())
                throw std::runtime_error("tcpModbusConfig.connections must be an array");
            std::unordered_map<std::string, std::unique_ptr<modbusRuntime>> replacements;
            for (const nlohmann::json& item : message.payload.at("connections"))
            {
                modbusTcpConnectionConfig config = parse_modbus_tcp_config(item);
                if (replacements.contains(config.modbus.id))
                    throw std::runtime_error("Duplicate Modbus TCP connection id: " + config.modbus.id);
                auto runtime = std::make_unique<modbusRuntime>(core::interprocess::messageProtocol_);
                runtime->apply_tcp(config);
                apply_pending_anomaly_rules(pendingAnomalyRules, "modbusTcp", config.modbus.id, *runtime);
                replacements.emplace(config.modbus.id, std::move(runtime));
            }
            runtimes = std::move(replacements);
            SPDLOG_INFO("Applied Modbus TCP config message {} connections={}", message.messageId, runtimes.size());
        }

        void apply_sensor_anomaly_config(
            const module::message_protocol::messageProtocol::configMessage& message,
            std::array<rs232Runtime, 2>& rs232Runtimes,
            std::array<std::unique_ptr<modbusRuntime>, 2>& rtuRuntimes,
            std::unordered_map<std::string, std::unique_ptr<modbusRuntime>>& tcpRuntimes,
            std::unordered_map<std::string, nlohmann::json>& pendingAnomalyRules)
        {
            const std::string sourceType = message.payload.value("source_type", std::string{});
            const std::string sourceId = message.payload.value("source_id", std::string{});
            if (sourceType.empty() || sourceId.empty())
                throw std::runtime_error("sensorAnomalyConfig needs source_type and source_id");

            pendingAnomalyRules[anomaly_rules_key(sourceType, sourceId)] = message.payload;

            bool applied = false;
            if (sourceType == "rs232Sensor")
            {
                for (rs232Runtime& runtime : rs232Runtimes)
                {
                    if (runtime.port_name() == sourceId)
                    {
                        runtime.apply_anomaly_rules(message.payload);
                        applied = true;
                        break;
                    }
                }
            }
            else if (sourceType == "modbusRtu")
            {
                for (std::unique_ptr<modbusRuntime>& runtime : rtuRuntimes)
                {
                    if (runtime->source_id() == sourceId)
                    {
                        runtime->apply_anomaly_rules(message.payload);
                        applied = true;
                        break;
                    }
                }
            }
            else if (sourceType == "modbusTcp")
            {
                const auto it = tcpRuntimes.find(sourceId);
                if (it != tcpRuntimes.end())
                {
                    it->second->apply_anomaly_rules(message.payload);
                    applied = true;
                }
            }
            else
            {
                throw std::runtime_error("Unsupported sensorAnomalyConfig source_type: " + sourceType);
            }

            SPDLOG_INFO("sensorAnomalyConfig for {} {} {}", sourceType, sourceId,
                applied ? "applied immediately" : "stored pending (runtime not active yet)");
        }
    }

    void main()
    {
        std::array<rs232Runtime, 2> runtimes {{
            rs232Runtime{core::interprocess::messageProtocol_},
            rs232Runtime{core::interprocess::messageProtocol_},
        }};
        std::array<std::unique_ptr<modbusRuntime>, 2> rtuRuntimes {{
            std::make_unique<modbusRuntime>(core::interprocess::messageProtocol_),
            std::make_unique<modbusRuntime>(core::interprocess::messageProtocol_),
        }};
        std::unordered_map<std::string, std::unique_ptr<modbusRuntime>> tcpRuntimes;
        std::unordered_map<std::string, nlohmann::json> pendingAnomalyRules;
        SPDLOG_INFO("Sensor process thread running");

        while (true)
        {
            while (auto message = core::interprocess::messageProtocol_.get_next_config())
            {
                try
                {
                    if (message->messageType == "rs232Config")
                        apply_rs232_config(*message, runtimes, pendingAnomalyRules);
                    else if (message->messageType == "rs485ModbusConfig")
                        apply_rs485_config(*message, rtuRuntimes, pendingAnomalyRules);
                    else if (message->messageType == "tcpModbusConfig")
                        apply_modbus_tcp_config(*message, tcpRuntimes, pendingAnomalyRules);
                    else if (message->messageType == "sensorAnomalyConfig")
                        apply_sensor_anomaly_config(*message, runtimes, rtuRuntimes, tcpRuntimes, pendingAnomalyRules);
                    else
                        SPDLOG_WARN("Unsupported queued sensor config {}", message->messageType);
                }
                catch (const std::exception& exception)
                {
                    SPDLOG_ERROR("Failed to apply {} message {}: {}",
                        message->messageType, message->messageId, exception.what());
                }
            }

            for (rs232Runtime& runtime : runtimes) runtime.loop();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
}
