#include "gateway/modules/message_protocol/message_protocol.hpp"

namespace module::message_protocol
{

    messageProtocol::messageProtocol()
    {
        std::random_device rd;
        startupRandom_ = (static_cast<std::uint64_t>(rd()) << 32) | rd();
    }
    messageProtocol::~messageProtocol()
    {
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
            tx_queue_.push(std::move(bytes));
        }
    }


    std::optional<std::vector<std::uint8_t>> messageProtocol::get_next_tx()
    {
         std::lock_guard<std::mutex> lock(tx_mutex_);

        if(tx_queue_.empty())
        {
          return std::nullopt;
        }

        auto data = std::move(tx_queue_.front());
        tx_queue_.pop();

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
