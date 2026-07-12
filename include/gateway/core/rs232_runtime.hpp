#pragma once

#include "gateway/core/sensor_config.hpp"
#include "gateway/modules/dustrak/drx_85xx.hpp"
#include "gateway/modules/message_protocol/message_protocol.hpp"
#include "gateway/modules/serial/serial.hpp"
#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

namespace core::sensorprocess
{
    class rs232Runtime
    {
    public:
        explicit rs232Runtime(module::message_protocol::messageProtocol& protocol);
        void apply(const rs232Config& config);
        void stop();
        void loop();
        const std::string& port_name() const;

    private:
        void loop_sniffer();
        void process_sniffer_buffer(bool idleExpired);
        void emit_frame(std::vector<std::uint8_t> frame);
        void capture_frame(const nlohmann::json& frame) const;

        module::message_protocol::messageProtocol& protocol_;
        rs232Config config_ {};
        module::serial::serialPort serial_ {};
        std::unique_ptr<module::dustrak::drx85xx> dustrak_ {};
        std::vector<std::uint8_t> snifferBuffer_ {};
        std::chrono::steady_clock::time_point lastByteAt_ {};
        bool running_ {false};
    };
}
