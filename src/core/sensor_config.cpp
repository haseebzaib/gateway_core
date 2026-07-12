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

        module::modbus::registerType parse_register_type(const std::string& value)
        {
            if (value == "holding_register") return module::modbus::registerType::Holding;
            if (value == "input_register") return module::modbus::registerType::Input;
            if (value == "coil") return module::modbus::registerType::Coil;
            if (value == "discrete_input") return module::modbus::registerType::DiscreteInput;
            throw std::runtime_error("Unsupported Modbus register_type: " + value);
        }

        module::modbus::dataType parse_data_type(const std::string& value)
        {
            if (value == "int16") return module::modbus::dataType::Int16;
            if (value == "uint16") return module::modbus::dataType::UInt16;
            if (value == "int32") return module::modbus::dataType::Int32;
            if (value == "uint32") return module::modbus::dataType::UInt32;
            if (value == "float32") return module::modbus::dataType::Float32;
            if (value == "bool") return module::modbus::dataType::Bool;
            throw std::runtime_error("Unsupported Modbus data_type: " + value);
        }

        std::vector<module::modbus::registerConfig> parse_registers(const nlohmann::json& value)
        {
            if (!value.is_array()) throw std::runtime_error("Modbus registers must be an array");
            std::vector<module::modbus::registerConfig> registers;
            for (const nlohmann::json& item : value)
            {
                if (!item.is_object()) throw std::runtime_error("Modbus register must be an object");
                module::modbus::registerConfig config;
                config.name = item.value("name", std::string{});
                if (config.name.empty()) throw std::runtime_error("Modbus register name cannot be empty");
                config.registerType_ = parse_register_type(item.value("register_type", std::string{"holding_register"}));
                config.address = item.value("address", 0);
                if (config.address < 0 || config.address > 65535) throw std::runtime_error("Modbus register address out of range");
                config.dataType_ = parse_data_type(item.value("data_type", std::string{"uint16"}));
                const std::string order = item.value("word_order", std::string{"big"});
                if (order != "big" && order != "little") throw std::runtime_error("Unsupported Modbus word_order: " + order);
                config.wordOrder_ = order == "little" ? module::modbus::wordOrder::Little : module::modbus::wordOrder::Big;
                config.scale = item.value("scale", 1.0);
                config.unit = item.value("unit", std::string{});
                registers.push_back(std::move(config));
            }
            return registers;
        }

        char modbus_parity(const std::string& value)
        {
            if (value == "none") return 'N';
            if (value == "even") return 'E';
            if (value == "odd") return 'O';
            throw std::runtime_error("Unsupported serial parity: " + value);
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

    rs485Config parse_rs485_port_config(
        const std::string& portName,
        const std::string& devicePath,
        const nlohmann::json& payload)
    {
        if (!payload.is_object()) throw std::runtime_error(portName + " must be an object");
        rs485Config config;
        config.portName = portName;
        config.enabled = payload.value("enabled", false);
        const nlohmann::json serial = payload.value("serial", nlohmann::json::object());
        const nlohmann::json rtu = payload.value("modbus_rtu", nlohmann::json::object());
        config.modbus.name = portName;
        config.modbus.devicePath = devicePath;
        config.modbus.baudRate = serial.value("baud_rate", 9600);
        config.modbus.parity = modbus_parity(serial.value("parity", std::string{"none"}));
        config.modbus.dataBits = serial.value("data_bits", 8);
        config.modbus.stopBits = serial.value("stop_bits", 1);
        config.modbus.slaveAddress = rtu.value("slave_address", 1);
        if (config.modbus.slaveAddress < 1 || config.modbus.slaveAddress > 247)
            throw std::runtime_error("Modbus RTU slave_address out of range");
        config.modbus.pollInterval = std::chrono::milliseconds(std::clamp(rtu.value("poll_interval_ms", 1000), 50, 3600000));
        config.modbus.responseTimeout = std::chrono::milliseconds(1000);
        config.modbus.registers = parse_registers(rtu.value("registers", nlohmann::json::array()));
        return config;
    }

    modbusTcpConnectionConfig parse_modbus_tcp_config(const nlohmann::json& payload)
    {
        if (!payload.is_object()) throw std::runtime_error("Modbus TCP connection must be an object");
        modbusTcpConnectionConfig config;
        config.enabled = payload.value("enabled", false);
        config.modbus.id = payload.value("id", std::string{});
        if (config.modbus.id.empty()) throw std::runtime_error("Modbus TCP connection id cannot be empty");
        config.modbus.name = payload.value("name", config.modbus.id);
        config.modbus.interface = payload.value("interface", std::string{"eth0"});
        config.modbus.ip = payload.value("ip", std::string{});
        config.modbus.port = payload.value("port", 502);
        config.modbus.unitId = payload.value("unit_id", 1);
        if (config.enabled && config.modbus.ip.empty()) throw std::runtime_error("Enabled Modbus TCP connection needs an IP address");
        if (config.modbus.port < 1 || config.modbus.port > 65535) throw std::runtime_error("Modbus TCP port out of range");
        if (config.modbus.unitId < 1 || config.modbus.unitId > 247) throw std::runtime_error("Modbus TCP unit_id out of range");
        config.modbus.pollInterval = std::chrono::milliseconds(std::clamp(payload.value("poll_interval_ms", 1000), 50, 3600000));
        config.modbus.responseTimeout = std::chrono::milliseconds(1000);
        config.modbus.registers = parse_registers(payload.value("registers", nlohmann::json::array()));
        return config;
    }
}
