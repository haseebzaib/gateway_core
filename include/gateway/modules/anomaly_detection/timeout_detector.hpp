#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <variant>
#include "utility"
#include "chrono"
#include <unordered_map>
#include "gateway/modules/anomaly_detection/metric.hpp"
#include "gateway/modules/anomaly_detection/event.hpp"
#include "gateway/modules/anomaly_detection/detector.hpp"

namespace anomaly_detection
{

    struct timeoutRule
    {

        std::string metricName;
        std::uint64_t timeoutMS;
        severity severity_;
        std::string message;
    };

    class timeoutDetector : public baseDetector
    {

    public:
        explicit timeoutDetector(std::vector<timeoutRule> rules);
        std::string_view name() const override;
        std::vector<anomalyEvent> update(const metricSnapshot &snapshot) override;

    private:
       
        anomalyEvent make_event(const metricSample &sample, severity severity_, std::uint64_t timeoutMs, std::string_view message);

        std::unordered_map<std::string, std::uint64_t> lastSeenTimestampMs_;
        std::unordered_map<std::string, double> previousValue;
        std::vector<timeoutRule> rules_;
    };

}