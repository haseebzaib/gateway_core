#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace gateway::model
{

enum class DeviceStatus
{
    Ok,
    Warning,
    Error,
};

struct MetricValue
{
    std::string name {};
    double value {0.0};
    std::string unit {};
    std::string quality {"good"};
    std::int64_t timestamp_ms {0};
};

struct DeviceError
{
    std::int64_t timestamp_ms {0};
    std::string severity {"warning"};
    std::string type {};
    std::string message {};
    std::string details_json {};
};

struct TransportInfo
{
    std::string type {};
    std::string endpoint {};
    std::string network_interface {};
    std::optional<int> port {};
    std::optional<int> slave_address {};
    std::optional<int> unit_id {};
};

struct DeviceState
{
    std::int64_t timestamp_ms {0};
    std::string source {};
    std::string device_id {};
    std::string name {};
    std::string device_type {};
    DeviceStatus status {DeviceStatus::Ok};
    TransportInfo transport {};
    std::vector<MetricValue> metrics {};
    std::optional<DeviceError> error {};
    std::string raw_json {};
};

} // namespace gateway::model

