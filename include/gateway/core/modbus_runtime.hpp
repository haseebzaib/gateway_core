#pragma once

#include "gateway/core/sensor_config.hpp"
#include "gateway/modules/message_protocol/message_protocol.hpp"
#include "gateway/modules/modbus/modbus_client.hpp"
#include <chrono>
#include <functional>
#include <stop_token>
#include <string>
#include <thread>

namespace core::sensorprocess
{
    class modbusRuntime
    {
    public:
        explicit modbusRuntime(module::message_protocol::messageProtocol& protocol);
        ~modbusRuntime();
        modbusRuntime(const modbusRuntime&) = delete;
        modbusRuntime& operator=(const modbusRuntime&) = delete;

        void apply_rtu(const rs485Config& config);
        void apply_tcp(const modbusTcpConnectionConfig& config);
        void stop();

    private:
        void start(
            std::string sourceType,
            std::string sourceId,
            std::chrono::milliseconds pollInterval,
            std::function<bool(module::modbus::client&)> connect);
        void run(
            std::stop_token stopToken,
            std::string sourceType,
            std::string sourceId,
            std::chrono::milliseconds pollInterval,
            std::function<bool(module::modbus::client&)> connect);

        module::message_protocol::messageProtocol& protocol_;
        std::jthread worker_ {};
    };
}
