#include "gateway/core/rs232_runtime.hpp"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace core::sensorprocess
{
    namespace
    {
        std::int64_t timestamp_ms()
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }

        std::string ascii_text(const std::vector<std::uint8_t>& bytes)
        {
            std::string result;
            result.reserve(bytes.size());
            for (const std::uint8_t byte : bytes)
                result.push_back(byte >= 32 && byte <= 126 ? static_cast<char>(byte) : '.');
            return result;
        }

        std::string hex_text(const std::vector<std::uint8_t>& bytes)
        {
            std::ostringstream output;
            output << std::hex << std::uppercase << std::setfill('0');
            for (std::size_t index = 0; index < bytes.size(); ++index)
            {
                if (index) output << ' ';
                output << std::setw(2) << static_cast<unsigned int>(bytes[index]);
            }
            return output.str();
        }

        // DustTrak measurement readings are a POSITIONAL array with no field
        // names (build_json_packet() in drx_85xx.cpp); index meaning comes
        // from the `channel` enum there: PM1=0, PM25=1, RespirablePM4=2,
        // PM10=3, Total=4 (5-channel DRX 8533/8534). Older DustTrak II
        // 8530/8532 report a single mass channel only. Anything else is
        // unexpected — name defensively by index rather than guess wrong.
        std::vector<anomaly_detection::metricSample> extract_dustrak_samples(const nlohmann::json& payload)
        {
            std::vector<anomaly_detection::metricSample> samples;
            if (!payload.contains("measurement") || !payload.at("measurement").is_object())
                return samples;

            const nlohmann::json& measurement = payload.at("measurement");
            if (!measurement.contains("values_mg_m3") || !measurement.at("values_mg_m3").is_array())
                return samples;

            const nlohmann::json& values = measurement.at("values_mg_m3");
            static constexpr const char* speciesNames[5] = {"pm1", "pm25", "pm4", "pm10", "total"};
            const std::uint64_t nowMs = static_cast<std::uint64_t>(timestamp_ms());

            for (std::size_t index = 0; index < values.size(); ++index)
            {
                if (!values[index].is_number()) continue;
                std::string name;
                if (values.size() == 5) name = speciesNames[index];
                else if (values.size() == 1) name = "mass";
                else name = "channel_" + std::to_string(index);

                samples.push_back({
                    .name = std::move(name),
                    .value = values[index].get<double>(),
                    .timestamp_ms = nowMs,
                    .type = anomaly_detection::metricType::Gauge,
                });
            }
            return samples;
        }
    }

    rs232Runtime::rs232Runtime(module::message_protocol::messageProtocol& protocol)
        : protocol_(protocol)
    {
    }

    void rs232Runtime::apply(const rs232Config& config)
    {
        stop();
        config_ = config;
        if (!config_.enabled)
        {
            SPDLOG_INFO("RS232 {} disabled", config_.portName);
            return;
        }
        if (!serial_.open(config_.serial))
        {
            SPDLOG_ERROR("RS232 {} failed to open {}", config_.portName, config_.devicePath);
            return;
        }
        running_ = true;
        if (config_.mode == rs232Mode::Sensor)
        {
            if (config_.sensor != "dustrak")
            {
                SPDLOG_ERROR("RS232 {} unsupported sensor {}", config_.portName, config_.sensor);
                stop();
                return;
            }
            dustrak_ = std::make_unique<module::dustrak::drx85xx>();
            dustrak_->configure(config_.dustrak);
            dustrak_->init(serial_);
            SPDLOG_INFO("RS232 {} running Dustrak on {}", config_.portName, config_.devicePath);
        }
        else
        {
            lastByteAt_ = std::chrono::steady_clock::now();
            SPDLOG_INFO("RS232 {} sniffer started on {} (RX only)", config_.portName, config_.devicePath);
        }
    }

    void rs232Runtime::stop()
    {
        running_ = false;
        dustrak_.reset();
        serial_.close();
        snifferBuffer_.clear();
        lastPublishedMeasurementMs_ = 0;
    }

    void rs232Runtime::loop()
    {
        if (!running_) return;
        if (config_.mode == rs232Mode::Sniffer)
        {
            loop_sniffer();
            return;
        }
        std::string packet;
        dustrak_->loop(packet);
        const std::int64_t measurementTimestamp = dustrak_->last_measurement_timestamp_ms();
        if (measurementTimestamp > 0 && measurementTimestamp != lastPublishedMeasurementMs_ && !packet.empty())
        {
            const nlohmann::json payload = nlohmann::json::parse(packet, nullptr, false);
            if (!payload.is_discarded())
            {
                SPDLOG_INFO("rs232Sensor {} reading {}", config_.portName, payload.dump());
                protocol_.send_sensor_payload("rs232Sensor", config_.portName, payload);
                SPDLOG_INFO("rs232Sensor {} forwarded to hub", config_.portName);
                lastPublishedMeasurementMs_ = measurementTimestamp;
                evaluate_anomalies(extract_dustrak_samples(payload));
            }
        }
    }

    const std::string& rs232Runtime::port_name() const
    {
        return config_.portName;
    }

    void rs232Runtime::apply_anomaly_rules(const nlohmann::json& payload)
    {
        const sensorAnomalyConfig config = parse_sensor_anomaly_config(payload);

        std::vector<std::unique_ptr<anomaly_detection::baseDetector>> detectors;
        detectors.push_back(std::make_unique<anomaly_detection::thresholdDetector>(config.thresholdRules));
        detectors.push_back(std::make_unique<anomaly_detection::rangeCheckDetector>(config.rangeRules));
        detectors.push_back(std::make_unique<anomaly_detection::deltaDetection>(config.deltaRules));
        detectors.push_back(std::make_unique<anomaly_detection::slopeDetection>(config.slopeRules));
        detectors.push_back(std::make_unique<anomaly_detection::zScoreDetection>(config.zScoreRules));
        detectors.push_back(std::make_unique<anomaly_detection::timeoutDetector>(config.timeoutRules));
        detectors.push_back(std::make_unique<anomaly_detection::multiConditionDetector>(config.multiConditionRules));

        std::lock_guard<std::mutex> lock(anomalyMutex_);
        anomalyDetectors_ = std::move(detectors);
        SPDLOG_INFO("{} {} anomaly rules applied (threshold={} range={} delta={} slope={} z_score={} timeout={} multi_condition={})",
            config.sourceType, config.sourceId,
            config.thresholdRules.size(), config.rangeRules.size(), config.deltaRules.size(),
            config.slopeRules.size(), config.zScoreRules.size(), config.timeoutRules.size(),
            config.multiConditionRules.size());
    }

    void rs232Runtime::evaluate_anomalies(const std::vector<anomaly_detection::metricSample>& samples)
    {
        if (samples.empty()) return;

        anomaly_detection::metricSnapshot snapshot;
        snapshot.timestamp_ms = samples.front().timestamp_ms;
        snapshot.samples = samples;

        std::vector<anomaly_detection::anomalyEvent> allEvents;
        {
            std::lock_guard<std::mutex> lock(anomalyMutex_);
            for (const std::unique_ptr<anomaly_detection::baseDetector>& detector : anomalyDetectors_)
            {
                std::vector<anomaly_detection::anomalyEvent> events = detector->update(snapshot);
                allEvents.insert(allEvents.end(), events.begin(), events.end());
            }
        }

        if (!allEvents.empty())
        {
            protocol_.send_sensor_anomaly_data("rs232Sensor", config_.portName, allEvents);
        }
    }

    void rs232Runtime::loop_sniffer()
    {
        std::vector<std::uint8_t> bytes;
        if (serial_.read_some(bytes, 4096) && !bytes.empty())
        {
            lastByteAt_ = std::chrono::steady_clock::now();
            if (config_.sniffer.framing == snifferFraming::Raw)
            {
                emit_frame(std::move(bytes));
                return;
            }
            const std::size_t room = config_.sniffer.maxLiveBufferBytes > snifferBuffer_.size()
                ? config_.sniffer.maxLiveBufferBytes - snifferBuffer_.size() : 0;
            if (bytes.size() > room)
            {
                SPDLOG_WARN("RS232 {} sniffer buffer overflow; dropping {} buffered bytes", config_.portName, snifferBuffer_.size());
                snifferBuffer_.clear();
            }
            snifferBuffer_.insert(snifferBuffer_.end(), bytes.begin(), bytes.end());
            process_sniffer_buffer(false);
        }
        else if (config_.sniffer.framing == snifferFraming::IdleGap && !snifferBuffer_.empty())
        {
            const auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - lastByteAt_).count();
            process_sniffer_buffer(idle >= config_.sniffer.idleGapMs);
        }
    }

    void rs232Runtime::process_sniffer_buffer(bool idleExpired)
    {
        if (config_.sniffer.framing == snifferFraming::FixedLength)
        {
            while (snifferBuffer_.size() >= config_.sniffer.fixedFrameBytes)
            {
                std::vector<std::uint8_t> frame(snifferBuffer_.begin(), snifferBuffer_.begin() + config_.sniffer.fixedFrameBytes);
                snifferBuffer_.erase(snifferBuffer_.begin(), snifferBuffer_.begin() + config_.sniffer.fixedFrameBytes);
                emit_frame(std::move(frame));
            }
            return;
        }
        if (config_.sniffer.framing == snifferFraming::Line)
        {
            const std::vector<std::uint8_t> delimiter(config_.sniffer.lineDelimiter.begin(), config_.sniffer.lineDelimiter.end());
            while (true)
            {
                const auto found = std::search(snifferBuffer_.begin(), snifferBuffer_.end(), delimiter.begin(), delimiter.end());
                if (found == snifferBuffer_.end()) break;
                const auto end = found + static_cast<std::ptrdiff_t>(delimiter.size());
                std::vector<std::uint8_t> frame(snifferBuffer_.begin(), end);
                snifferBuffer_.erase(snifferBuffer_.begin(), end);
                emit_frame(std::move(frame));
            }
            return;
        }
        if (config_.sniffer.framing == snifferFraming::IdleGap && idleExpired)
        {
            std::vector<std::uint8_t> frame;
            frame.swap(snifferBuffer_);
            emit_frame(std::move(frame));
        }
    }

    void rs232Runtime::emit_frame(std::vector<std::uint8_t> frame)
    {
        if (frame.empty()) return;
        const std::string hex = hex_text(frame);
        nlohmann::json data = {
            {"port", config_.portName},
            {"device_path", config_.devicePath},
            {"timestamp_ms", timestamp_ms()},
            {"size", frame.size()},
            {"ascii", ascii_text(frame)},
            {"hex", hex}
        };
        SPDLOG_INFO("rs232Sniffer {} frame size={} hex={}", config_.portName, frame.size(), hex);
        protocol_.send_rs232_sniffer_frame(data);
        SPDLOG_INFO("rs232Sniffer {} forwarded to hub", config_.portName);
    }
}
