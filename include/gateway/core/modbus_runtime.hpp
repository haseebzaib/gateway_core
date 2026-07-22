#pragma once

#include "gateway/core/sensor_anomaly_config.hpp"
#include "gateway/core/sensor_config.hpp"
#include "gateway/modules/message_protocol/message_protocol.hpp"
#include "gateway/modules/modbus/modbus_client.hpp"
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

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

        // Rebuilds this connection's own anomaly detectors from a
        // sensorAnomalyConfig JSON payload (see sensor_anomaly_config.hpp).
        // Safe to call at any time; does not touch the Modbus connection
        // itself (no reconnect), only the detector rules.
        void apply_anomaly_rules(const nlohmann::json& payload);

        // Set once by apply_rtu/apply_tcp, before the worker thread starts.
        // Lets sensorprocess.cpp find an already-running fixed-slot RTU
        // runtime by source id when a sensorAnomalyConfig message arrives
        // independently of any rs485ModbusConfig resend.
        const std::string& source_id() const { return sourceId_; }

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
        void evaluate_anomalies(
            const std::string& sourceType,
            const std::string& sourceId,
            const std::vector<module::modbus::sample>& samples);

        module::message_protocol::messageProtocol& protocol_;
        std::jthread worker_ {};
        std::string sourceId_ {};

        std::mutex anomalyMutex_ {};
        std::vector<std::unique_ptr<anomaly_detection::baseDetector>> anomalyDetectors_ {};
    };
}
