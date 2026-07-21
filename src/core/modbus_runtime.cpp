#include "gateway/core/modbus_runtime.hpp"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <chrono>
#include <sstream>
#include <thread>

namespace core::sensorprocess
{
    modbusRuntime::modbusRuntime(module::message_protocol::messageProtocol& protocol)
        : protocol_(protocol)
    {
    }

    modbusRuntime::~modbusRuntime()
    {
        stop();
    }

    void modbusRuntime::apply_rtu(const rs485Config& config)
    {
        stop();
        if (!config.enabled)
        {
            SPDLOG_INFO("Modbus RTU {} disabled", config.portName);
            return;
        }
        start("modbusRtu", config.portName, config.modbus.pollInterval,
            [settings = config.modbus](module::modbus::client& client) { return client.connect_rtu(settings); });
    }

    void modbusRuntime::apply_tcp(const modbusTcpConnectionConfig& config)
    {
        stop();
        if (!config.enabled)
        {
            SPDLOG_INFO("Modbus TCP {} disabled", config.modbus.id);
            return;
        }
        start("modbusTcp", config.modbus.id, config.modbus.pollInterval,
            [settings = config.modbus](module::modbus::client& client) { return client.connect_tcp(settings); });
    }

    void modbusRuntime::stop()
    {
        if (!worker_.joinable()) return;
        worker_.request_stop();
        worker_.join();
    }

    void modbusRuntime::start(
        std::string sourceType,
        std::string sourceId,
        std::chrono::milliseconds pollInterval,
        std::function<bool(module::modbus::client&)> connect)
    {
        worker_ = std::jthread(
            [this, sourceType = std::move(sourceType), sourceId = std::move(sourceId), pollInterval, connect = std::move(connect)](std::stop_token token) mutable {
                run(token, std::move(sourceType), std::move(sourceId), pollInterval, std::move(connect));
            });
    }

    void modbusRuntime::run(
        std::stop_token stopToken,
        std::string sourceType,
        std::string sourceId,
        std::chrono::milliseconds pollInterval,
        std::function<bool(module::modbus::client&)> connect)
    {
        module::modbus::client client;
        constexpr auto reconnectDelay = std::chrono::seconds(2);
        auto nextConnect = std::chrono::steady_clock::now();
        auto nextPoll = nextConnect;

        while (!stopToken.stop_requested())
        {
            const auto now = std::chrono::steady_clock::now();
            if (!client.is_connected())
            {
                if (now >= nextConnect)
                {
                    if (connect(client))
                    {
                        SPDLOG_INFO("{} {} worker connected", sourceType, sourceId);
                        nextPoll = std::chrono::steady_clock::now();
                    }
                    else
                    {
                        protocol_.send_modbus_status(sourceType, sourceId, "disconnected", "connection failed");
                        nextConnect = std::chrono::steady_clock::now() + reconnectDelay;
                    }
                }
            }
            else if (now >= nextPoll)
            {
                std::vector<module::modbus::sample> samples;
                const bool success = client.poll(samples);

                if (success)
                {
                    std::ostringstream summary;
                    for (const auto& sample : samples)
                    {
                        summary << ' ' << sample.name << '=' << sample.value << sample.unit;
                    }
                    SPDLOG_INFO("{} {} poll ok samples={}{}", sourceType, sourceId, samples.size(), summary.str());
                }
                else
                {
                    for (const auto& error : client.last_errors())
                    {
                        SPDLOG_WARN("{} {} poll failed register={} address={} error={}",
                            sourceType, sourceId, error.name, error.source.address, error.message);
                    }
                }

                protocol_.send_modbus_samples(sourceType, sourceId, samples, client.last_errors(), success);
                SPDLOG_INFO("{} {} forwarded {} sample(s) to hub (ok={})", sourceType, sourceId, samples.size(), success);
                if (client.connection_lost())
                {
                    client.disconnect();
                    nextConnect = std::chrono::steady_clock::now() + reconnectDelay;
                }
                nextPoll = std::chrono::steady_clock::now() + pollInterval;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        client.disconnect();
        SPDLOG_INFO("{} {} worker stopped", sourceType, sourceId);
    }
}
