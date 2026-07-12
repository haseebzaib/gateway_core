#include "gateway/core/sensor_config.hpp"
#include <algorithm>
#include <stdexcept>

namespace core::sensorprocess
{
    namespace
    {
        bool boolean(const nlohmann::json& value, const char* key, bool fallback)
        {
            return value.contains(key) && value.at(key).is_boolean() ? value.at(key).get<bool>() : fallback;
        }

        module::serial::parity parse_parity(const std::string& value)
        {
            if (value == "none") return module::serial::parity::None;
            if (value == "even") return module::serial::parity::Even;
            if (value == "odd") return module::serial::parity::Odd;
            throw std::runtime_error("Unsupported serial parity: " + value);
        }

        snifferFraming parse_framing(const std::string& value)
        {
            if (value == "raw") return snifferFraming::Raw;
            if (value == "line") return snifferFraming::Line;
            if (value == "fixed_length") return snifferFraming::FixedLength;
            if (value == "idle_gap") return snifferFraming::IdleGap;
            throw std::runtime_error("Unsupported sniffer framing: " + value);
        }

        std::string parse_delimiter(const std::string& value)
        {
            if (value == "cr") return "\r";
            if (value == "lf") return "\n";
            if (value == "crlf") return "\r\n";
            throw std::runtime_error("Unsupported line delimiter: " + value);
        }
    }

    rs232Config parse_rs232_port_config(
        const std::string& portName,
        const std::string& devicePath,
        const nlohmann::json& payload)
    {
        if (!payload.is_object()) throw std::runtime_error(portName + " must be an object");
        rs232Config config;
        config.portName = portName;
        config.devicePath = devicePath;
        config.enabled = payload.value("enabled", false);
        config.sensor = payload.value("sensor", std::string{"dustrak"});
        config.source = payload;

        const std::string mode = payload.value("mode", std::string{"sensor"});
        if (mode == "sensor") config.mode = rs232Mode::Sensor;
        else if (mode == "sniffer") config.mode = rs232Mode::Sniffer;
        else throw std::runtime_error("Unsupported RS232 mode: " + mode);

        const nlohmann::json serial = payload.value("serial", nlohmann::json::object());
        config.serial.devicePath_ = devicePath;
        config.serial.baudRate_ = serial.value("baud_rate", 9600U);
        config.serial.charSize_ = serial.value("data_bits", 8U);
        config.serial.parity_ = parse_parity(serial.value("parity", std::string{"none"}));
        const int stopBits = serial.value("stop_bits", 1);
        if (stopBits != 1 && stopBits != 2) throw std::runtime_error("stop_bits must be 1 or 2");
        config.serial.stopBit_ = stopBits == 2 ? module::serial::stopBits::Two : module::serial::stopBits::One;
        config.serial.startupSettleDelayMs_ = config.mode == rs232Mode::Sniffer ? 0 : 500;
        config.serial.txPostWriteDelayMs_ = config.mode == rs232Mode::Sniffer ? 0 : 500;
        config.serial.rxTimeoutMs_ = config.mode == rs232Mode::Sniffer ? 20 : 300;

        const nlohmann::json dustrak = payload.value("dustrak", nlohmann::json::object());
        const nlohmann::json polling = dustrak.value("polling", nlohmann::json::object());
        const nlohmann::json driver = dustrak.value("driver", nlohmann::json::object());
        config.dustrak.polling.readIdentityOnInit = boolean(polling, "read_identity_on_init", true);
        config.dustrak.polling.pollStatus = boolean(polling, "poll_status", true);
        config.dustrak.polling.autoStartMeasurement = boolean(polling, "auto_start_measurement", false);
        config.dustrak.polling.pollMeasurements = boolean(polling, "poll_measurements", true);
        config.dustrak.polling.pollMeasurementStats = boolean(polling, "poll_measurement_stats", false);
        config.dustrak.polling.pollFaultMessages = boolean(polling, "poll_fault_messages", false);
        config.dustrak.polling.pollAlarmMessages = boolean(polling, "poll_alarm_messages", false);
        config.dustrak.polling.pollLogInfo = boolean(polling, "poll_log_info", false);
        config.dustrak.updateRamAfterWrite = boolean(driver, "update_ram_after_write", true);

        const nlohmann::json sniffer = payload.value("sniffer", nlohmann::json::object());
        config.sniffer.displayFormat = sniffer.value("display_format", std::string{"ascii_hex"});
        config.sniffer.framing = parse_framing(sniffer.value("framing", std::string{"line"}));
        config.sniffer.lineDelimiter = parse_delimiter(sniffer.value("line_delimiter", std::string{"crlf"}));
        config.sniffer.fixedFrameBytes = std::clamp<std::size_t>(sniffer.value("fixed_frame_bytes", 32U), 1, 65536);
        config.sniffer.idleGapMs = std::clamp(sniffer.value("idle_gap_ms", 100), 1, 60000);
        config.sniffer.timestamp = sniffer.value("timestamp", true);
        config.sniffer.maxLiveBufferBytes = std::clamp<std::size_t>(sniffer.value("max_live_buffer_bytes", 1024U * 1024U), 4096, 16U * 1024U * 1024U);
        const nlohmann::json capture = sniffer.value("capture", nlohmann::json::object());
        config.sniffer.capture.enabled = capture.value("enabled", false);
        config.sniffer.capture.retentionDays = std::clamp(capture.value("retention_days", 7), 1, 365);
        config.sniffer.capture.maxSizeMb = std::clamp(capture.value("max_size_mb", 100), 1, 10240);
        return config;
    }
}
