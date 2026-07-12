#pragma once

#include "gateway/modules/dustrak/drx_85xx.hpp"
#include "gateway/modules/serial/serial.hpp"
#include "gateway/modules/modbus/modbus_client.hpp"
#include "gateway/utils/thirdparty/json.hpp"
#include <cstddef>
#include <string>

namespace core::sensorprocess
{
    enum class rs232Mode { Sensor, Sniffer };
    enum class snifferFraming { Raw, Line, FixedLength, IdleGap };

    struct snifferCaptureConfig
    {
        bool enabled {false};
        int retentionDays {7};
        int maxSizeMb {100};
    };

    struct snifferConfig
    {
        std::string displayFormat {"ascii_hex"};
        snifferFraming framing {snifferFraming::Line};
        std::string lineDelimiter {"\r\n"};
        std::size_t fixedFrameBytes {32};
        int idleGapMs {100};
        bool timestamp {true};
        std::size_t maxLiveBufferBytes {1024 * 1024};
        snifferCaptureConfig capture {};
    };

    struct rs232Config
    {
        std::string portName {};
        std::string devicePath {};
        bool enabled {false};
        rs232Mode mode {rs232Mode::Sensor};
        std::string sensor {"dustrak"};
        module::serial::serialConfig serial {};
        module::dustrak::drx85xx::driverConfig dustrak {};
        snifferConfig sniffer {};
        nlohmann::json source {};
    };

    struct rs485Config
    {
        std::string portName {};
        bool enabled {false};
        module::modbus::rtuConfig modbus {};
    };

    struct modbusTcpConnectionConfig
    {
        bool enabled {false};
        module::modbus::tcpConfig modbus {};
    };

    rs232Config parse_rs232_port_config(
        const std::string& portName,
        const std::string& devicePath,
        const nlohmann::json& payload);
    rs485Config parse_rs485_port_config(
        const std::string& portName,
        const std::string& devicePath,
        const nlohmann::json& payload);
    modbusTcpConnectionConfig parse_modbus_tcp_config(const nlohmann::json& payload);
}
