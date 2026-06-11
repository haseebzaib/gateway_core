#pragma once
#include "chrono"
#include <array>
#include <string_view>

namespace core::sensorprocess 
{

    constexpr std::string_view rs232Ch0Path = "/dev/ttyAMA2";
    constexpr std::string_view rs232Ch1Path = "/dev/ttyAMA3";
    constexpr std::string_view rs485Ch2Path = "/dev/ttyAMA4";
    constexpr std::string_view rs485Ch3Path = "/dev/ttyAMA0";

    struct rs232PortMapping {
     std::string_view port;
     std::string_view peripheralPath;
     std::uint16_t map;
    };

    struct rs485PortMapping {
     std::string_view port;
     std::string_view peripheralPath;
     std::uint16_t map;
    };



    void main();
}