#include "gateway/core/rs232_runtime.hpp"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
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

        std::string utc_date()
        {
            const std::time_t now = std::time(nullptr);
            std::tm value {};
            gmtime_r(&now, &value);
            std::ostringstream output;
            output << std::put_time(&value, "%Y-%m-%d");
            return output.str();
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
                protocol_.send_sensor_payload("rs232Sensor", config_.portName, payload);
                lastPublishedMeasurementMs_ = measurementTimestamp;
            }
        }
    }

    const std::string& rs232Runtime::port_name() const
    {
        return config_.portName;
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
        nlohmann::json data = {
            {"port", config_.portName},
            {"device_path", config_.devicePath},
            {"timestamp_ms", timestamp_ms()},
            {"size", frame.size()},
            {"ascii", ascii_text(frame)},
            {"hex", hex_text(frame)}
        };
        protocol_.send_rs232_sniffer_frame(data);
        if (config_.sniffer.capture.enabled) capture_frame(data);
    }

    void rs232Runtime::capture_frame(const nlohmann::json& frame) const
    {
        try
        {
            const char* configuredRoot = std::getenv("GATEWAY_INTERFACES_CAPTURE_DIR");
            const std::filesystem::path root = configuredRoot && *configuredRoot
                ? configuredRoot : "/opt/metacrust/data/gateway_interfaces/rs232";
            const std::filesystem::path directory = root / config_.portName;
            std::filesystem::create_directories(directory);
            const std::filesystem::path path = directory / (utc_date() + ".jsonl");
            const std::uintmax_t maximum = static_cast<std::uintmax_t>(config_.sniffer.capture.maxSizeMb) * 1024 * 1024;
            if (std::filesystem::exists(path) && std::filesystem::file_size(path) >= maximum)
            {
                SPDLOG_WARN("RS232 {} capture file reached {} MB; frame not persisted", config_.portName, config_.sniffer.capture.maxSizeMb);
                return;
            }
            std::ofstream output(path, std::ios::app);
            if (!output) throw std::runtime_error("cannot open " + path.string());
            output << frame.dump() << '\n';
        }
        catch (const std::exception& exception)
        {
            SPDLOG_ERROR("RS232 {} capture failed: {}", config_.portName, exception.what());
        }
    }
}
