#include "gateway/modules/message_protocol/message_protocol.hpp"
#include <stdexcept>
#include <chrono>

namespace module::message_protocol
{
    namespace
    {
        std::string_view severity_text(anomaly_detection::severity severity)
        {
            switch (severity)
            {
            case anomaly_detection::severity::Info:
                return "Info";
            case anomaly_detection::severity::Warning:
                return "Warning";
            case anomaly_detection::severity::Critical:
                return "Critical";
            }

            return "Unknown";
        }
    }

    messageProtocol::messageProtocol()
    {
        std::random_device rd;
        startupRandom_ = (static_cast<std::uint64_t>(rd()) << 32) | rd();
    }
    messageProtocol::~messageProtocol()
    {
    }

    void messageProtocol::receive(std::span<const std::uint8_t> bytes)
    {
        constexpr std::size_t maximum_frame_bytes = 1024 * 1024;
        rx_buffer_.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        if (rx_buffer_.size() > maximum_frame_bytes)
        {
            rx_buffer_.clear();
            nlohmann::json reply = {{"message_type", "nAck"}, {"error", "IPC frame exceeds maximum size"}};
            std::string output = reply.dump() + '\n';
            std::lock_guard<std::mutex> lock(tx_mutex_);
            tx_queue_.emplace_front(output.begin(), output.end());
            return;
        }

        std::size_t newline = 0;
        while ((newline = rx_buffer_.find('\n')) != std::string::npos)
        {
            std::string frame = rx_buffer_.substr(0, newline);
            rx_buffer_.erase(0, newline + 1);
            if (!frame.empty() && frame.back() == '\r') frame.pop_back();
            if (frame.empty()) continue;

            std::string messageId;
            try
            {
                const nlohmann::json message = nlohmann::json::parse(frame);
                if (!message.is_object()) throw std::runtime_error("IPC message must be a JSON object");
                messageId = message.value("message_id", std::string{});
                const std::string type = message.value("message_type", std::string{});

                const auto validate_payload = [&](const std::string& payloadKey) {
                    if (!message.contains(payloadKey) || !message.at(payloadKey).is_object())
                        throw std::runtime_error("Missing or invalid payload: " + payloadKey);
                };

                std::vector<std::string> payloadKeys;

                if (type == "rs232Config" || type == "rs485ModbusConfig" || type == "tcpModbusConfig" || type == "sensorAnomalyConfig")
                {
                    validate_payload(type);
                    payloadKeys.push_back(type);
                }
                else if (type == "combinedConfig")
                {
                    bool found = false;
                    for (const std::string key : {"rs232Config", "rs485ModbusConfig", "tcpModbusConfig"})
                    {
                        if (message.contains(key)) { validate_payload(key); payloadKeys.push_back(key); found = true; }
                    }
                    if (!found) throw std::runtime_error("combinedConfig contains no supported configuration");
                }
                else
                {
                    throw std::runtime_error("Unsupported message_type: " + type);
                }

                bool duplicate = false;
                {
                    std::lock_guard<std::mutex> lock(config_mutex_);
                    duplicate = !messageId.empty() && recent_message_id_set_.contains(messageId);
                    if (!duplicate)
                    {
                        for (const std::string& key : payloadKeys)
                            config_queue_.push({messageId, key, message.at(key)});
                        if (!messageId.empty())
                        {
                            recent_message_ids_.push_back(messageId);
                            recent_message_id_set_.insert(messageId);
                            if (recent_message_ids_.size() > 256)
                            {
                                recent_message_id_set_.erase(recent_message_ids_.front());
                                recent_message_ids_.pop_front();
                            }
                        }
                    }
                }

                if (message.value("ack_required", false))
                {
                    nlohmann::json reply = {
                        {"message_id", next_message_id()},
                        {"message_type", "ack"},
                        {"correlation_id", messageId},
                        {"status", duplicate ? "duplicate" : "accepted"}
                    };
                    std::string output = reply.dump() + '\n';
                    std::lock_guard<std::mutex> lock(tx_mutex_);
                    tx_queue_.emplace_front(output.begin(), output.end());
                }
            }
            catch (const std::exception& exception)
            {
                nlohmann::json reply = {
                    {"message_id", next_message_id()},
                    {"message_type", "nAck"},
                    {"correlation_id", messageId},
                    {"status", "rejected"},
                    {"error", exception.what()}
                };
                std::string output = reply.dump() + '\n';
                std::lock_guard<std::mutex> lock(tx_mutex_);
                tx_queue_.emplace_front(output.begin(), output.end());
            }
        }
    }

    std::optional<messageProtocol::configMessage> messageProtocol::get_next_config()
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        if (config_queue_.empty()) return std::nullopt;
        configMessage config = std::move(config_queue_.front());
        config_queue_.pop();
        return config;
    }

    void messageProtocol::send_device_data(deviceMetrics deviceData)
    {
        nlohmann::json msg;
        msg["message_id"] = next_message_id();
        // kept as enum: serializes to its underlying integer so the receiving
        // side can index straight into its function-pointer dispatch table.
        msg["message_type"] = messageType::deviceData;

        // all raw readings nested under "data"; the handler for deviceData
        // knows to parse this object.
        msg["data"] = {
            {"timestamp_ms",  deviceData.timestamp_ms},
            {"coreCount",     deviceData.coreCount},
            {"cpuUsage",      deviceData.cpuUsage},
            {"perCoreUsage",  deviceData.perCoreUsage},   // JSON array, len == coreCount
            {"cpuTemp",        deviceData.cpuTemp},
            {"perCoreFreqMhz", deviceData.perCoreFreqMhz},  // JSON array, len == coreCount
            {"loadAvg1m",     deviceData.loadAvg1m},
            {"loadAvg5m",     deviceData.loadAvg5m},
            {"loadAvg15m",    deviceData.loadAvg15m},
            {"throttleFlags", deviceData.throttleFlags},
            {"ramUsedMb",     deviceData.ramUsedMb},
            {"ramTotalMb",    deviceData.ramTotalMb},
            {"swapUsedMb",    deviceData.swapUsedMb},
            {"diskUsedPct",   deviceData.diskUsedPct},
            {"emmcUsedMb",    deviceData.emmcUsedMb},
            {"emmcTotalMb",   deviceData.emmcTotalMb},
            {"emmcLifeUsed",  deviceData.emmcLifeUsed},
            {"uptimeSec",     deviceData.uptimeSec}
        };

        // newline-delimited so the receiver can frame messages off the stream.
        std::string out = msg.dump();
        out.push_back('\n');
        std::vector<std::uint8_t> bytes(out.begin(), out.end());

        {
            std::lock_guard<std::mutex> lock(tx_mutex_);
            tx_queue_.push_back(std::move(bytes));
        }
    }

    void messageProtocol::send_device_anomaly_data(const std::vector<anomaly_detection::anomalyEvent>& anomalyEvents)
    {
        if (anomalyEvents.empty())
        {
            return;
        }

        nlohmann::json events = nlohmann::json::array();
        std::uint64_t latestTimestampMs = 0;

        for (const anomaly_detection::anomalyEvent& event : anomalyEvents)
        {
            if (event.timestamp_ms > latestTimestampMs)
            {
                latestTimestampMs = event.timestamp_ms;
            }

            events.push_back({
                {"timestamp_ms", event.timestamp_ms},
                {"detectorName", event.detectorName},
                {"metricName", event.metricName},
                {"severity", std::string{severity_text(event.severity_)}},
                {"value", event.value},
                {"zScore", event.zScore},
                {"deltaValue", event.deltaValue},
                {"slopeValue", event.slopeValue},
                {"message", event.message},
                {"criticalLimit", event.criticalLimit},
                {"warningLimit", event.warningLimit},
                {"minValue", event.minValue},
                {"maxValue", event.maxValue},
                {"warningDelta", event.warningDelta},
                {"criticalDelta", event.criticalDelta},
                {"warningSlopePerMin", event.warningSlopePerMin},
                {"criticalSlopePerMin", event.criticalSlopePerMin},
                {"triggerPositive", event.triggerPositive},
                {"alarmName", event.alarmName},
                {"warningZ", event.warningZ},
                {"criticalZ", event.criticalZ},
                {"slopeWindowMs", event.slopeWindowMs},
                {"timeoutMs", event.timeoutMs}
            });
        }

        nlohmann::json msg;
        msg["message_id"] = next_message_id();
        msg["message_type"] = messageType::deviceAnamoly;
        msg["data"] = {
            {"timestamp_ms", latestTimestampMs},
            {"event_count", anomalyEvents.size()},
            {"events", std::move(events)}
        };

        std::string out = msg.dump();
        out.push_back('\n');
        std::vector<std::uint8_t> bytes(out.begin(), out.end());

        {
            std::lock_guard<std::mutex> lock(tx_mutex_);
            tx_queue_.push_back(std::move(bytes));
        }
    }

    void messageProtocol::send_sensor_anomaly_data(
        std::string_view sourceType,
        std::string_view sourceId,
        const std::vector<anomaly_detection::anomalyEvent>& anomalyEvents)
    {
        if (anomalyEvents.empty())
        {
            return;
        }

        nlohmann::json events = nlohmann::json::array();
        std::uint64_t latestTimestampMs = 0;

        for (const anomaly_detection::anomalyEvent& event : anomalyEvents)
        {
            if (event.timestamp_ms > latestTimestampMs)
            {
                latestTimestampMs = event.timestamp_ms;
            }

            events.push_back({
                {"timestamp_ms", event.timestamp_ms},
                {"detectorName", event.detectorName},
                {"metricName", event.metricName},
                {"severity", std::string{severity_text(event.severity_)}},
                {"value", event.value},
                {"zScore", event.zScore},
                {"deltaValue", event.deltaValue},
                {"slopeValue", event.slopeValue},
                {"message", event.message},
                {"criticalLimit", event.criticalLimit},
                {"warningLimit", event.warningLimit},
                {"minValue", event.minValue},
                {"maxValue", event.maxValue},
                {"warningDelta", event.warningDelta},
                {"criticalDelta", event.criticalDelta},
                {"warningSlopePerMin", event.warningSlopePerMin},
                {"criticalSlopePerMin", event.criticalSlopePerMin},
                {"triggerPositive", event.triggerPositive},
                {"alarmName", event.alarmName},
                {"warningZ", event.warningZ},
                {"criticalZ", event.criticalZ},
                {"slopeWindowMs", event.slopeWindowMs},
                {"timeoutMs", event.timeoutMs}
            });
        }

        nlohmann::json msg;
        msg["message_id"] = next_message_id();
        msg["message_type"] = "sensorAnomaly";
        msg["data"] = {
            {"source_type", sourceType},
            {"source_id", sourceId},
            {"timestamp_ms", latestTimestampMs},
            {"event_count", anomalyEvents.size()},
            {"events", std::move(events)}
        };

        std::string out = msg.dump();
        out.push_back('\n');
        std::vector<std::uint8_t> bytes(out.begin(), out.end());

        {
            std::lock_guard<std::mutex> lock(tx_mutex_);
            tx_queue_.push_back(std::move(bytes));
        }
    }

    void messageProtocol::send_rs232_sniffer_frame(const nlohmann::json& data)
    {
        nlohmann::json message = {
            {"message_id", next_message_id()},
            {"message_type", "rs232SnifferFrame"},
            {"data", data}
        };
        std::string output = message.dump() + '\n';
        std::vector<std::uint8_t> bytes(output.begin(), output.end());
        std::lock_guard<std::mutex> lock(tx_mutex_);
        tx_queue_.push_back(std::move(bytes));
    }

    void messageProtocol::send_modbus_samples(
        std::string_view sourceType,
        std::string_view sourceId,
        const std::vector<module::modbus::sample>& samples,
        const std::vector<module::modbus::readError>& errors,
        bool success)
    {
        nlohmann::json values = nlohmann::json::array();
        for (const auto& sample : samples)
            values.push_back({{"name", sample.name}, {"value", sample.value}, {"unit", sample.unit}, {"address", sample.source.address}});
        nlohmann::json failures = nlohmann::json::array();
        for (const auto& error : errors)
            failures.push_back({{"name", error.name}, {"error", error.message}, {"address", error.source.address}});
        nlohmann::json message = {
            {"message_id", next_message_id()},
            {"message_type", "sensorData"},
            {"data", {
                {"source_type", sourceType},
                {"source_id", sourceId},
                {"timestamp_ms", static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count())},
                {"ok", success},
                {"samples", std::move(values)},
                {"errors", std::move(failures)}
            }}
        };
        std::string output = message.dump() + '\n';
        std::lock_guard<std::mutex> lock(tx_mutex_);
        tx_queue_.emplace_back(output.begin(), output.end());
    }

    void messageProtocol::send_modbus_status(
        std::string_view sourceType,
        std::string_view sourceId,
        std::string_view status,
        std::string_view error)
    {
        nlohmann::json message = {
            {"message_id", next_message_id()},
            {"message_type", "sensorStatus"},
            {"data", {{"source_type", sourceType}, {"source_id", sourceId}, {"status", status}, {"error", error}}}
        };
        std::string output = message.dump() + '\n';
        std::lock_guard<std::mutex> lock(tx_mutex_);
        tx_queue_.emplace_back(output.begin(), output.end());
    }

    void messageProtocol::send_sensor_payload(
        std::string_view sourceType,
        std::string_view sourceId,
        const nlohmann::json& payload,
        bool success)
    {
        nlohmann::json message = {
            {"message_id", next_message_id()},
            {"message_type", "sensorData"},
            {"data", {
                {"source_type", sourceType},
                {"source_id", sourceId},
                {"timestamp_ms", static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count())},
                {"ok", success},
                {"payload", payload}
            }}
        };
        std::string output = message.dump() + '\n';
        std::lock_guard<std::mutex> lock(tx_mutex_);
        tx_queue_.emplace_back(output.begin(), output.end());
    }


    std::optional<std::vector<std::uint8_t>> messageProtocol::get_next_tx()
    {
         std::lock_guard<std::mutex> lock(tx_mutex_);

        if(tx_queue_.empty())
        {
          return std::nullopt;
        }

        auto data = std::move(tx_queue_.front());
        tx_queue_.pop_front();

        return data;
    }

    std::uint64_t messageProtocol::next_message_id()
    {
        std::uint64_t counter = counter_.fetch_add(1, std::memory_order_relaxed);

        // Upper 32 bits: random boot/session ID
        // Lower 32 bits: increasing counter
        return (startupRandom_ & 0xFFFFFFFF00000000ULL) | (counter & 0xFFFFFFFFULL);
    }

}
