#include "gateway/core/sensorprocess.hpp"
#include "gateway/core/interprocess.hpp"
#include "gateway/core/rs232_runtime.hpp"
#include "gateway/core/sensor_config.hpp"
#include "spdlog/spdlog.h"
#include <array>
#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>

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

        void apply_rs232_config(
            const module::message_protocol::messageProtocol::configMessage& message,
            std::array<rs232Runtime, 2>& runtimes)
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
            }
            SPDLOG_INFO("Applied RS232 config message {}", message.messageId);
        }
    }

    void main()
    {
        std::array<rs232Runtime, 2> runtimes {{
            rs232Runtime{core::interprocess::messageProtocol_},
            rs232Runtime{core::interprocess::messageProtocol_},
        }};
        SPDLOG_INFO("Sensor process thread running");

        while (true)
        {
            while (auto message = core::interprocess::messageProtocol_.get_next_config())
            {
                try
                {
                    if (message->messageType == "rs232Config")
                        apply_rs232_config(*message, runtimes);
                    else
                        SPDLOG_INFO("Queued {} for a future sensor runtime", message->messageType);
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
