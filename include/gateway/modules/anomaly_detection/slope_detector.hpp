#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <string_view>

#include "gateway/modules/anomaly_detection/metric.hpp"
#include "gateway/modules/anomaly_detection/event.hpp"
#include "gateway/modules/anomaly_detection/detector.hpp"

namespace anomaly_detection
{
    struct slopeRule
    {
        std::string metricName;

        double warningSlopePerMin;
        double criticalSlopePerMin;

        std::uint64_t minElapsedMs;
        std::size_t minSamples;

        bool triggerPositive;

        std::uint64_t windowMs;

        /*
         * If time gap between two samples is larger than this,
         * history is considered broken and will be reset.
         *
         * Example:
         * sample interval = 10 sec
         * maxSampleGapMs = 30 sec
         */
        std::uint64_t maxSampleGapMs;

        std::string message;
    };

    class slopeDetection : public baseDetector
    {
    public:
        explicit slopeDetection(std::vector<slopeRule> rules);

        std::string_view name() const override;

        std::vector<anomalyEvent> update(const metricSnapshot& snapshot) override;

    private:
        anomalyEvent make_event(const metricSample& sample,
                                severity severity_,
                                double slopePerMin,
                                double warningSlopePerMin,
                                double criticalSlopePerMin,
                                bool triggerPositive,
                                std::uint64_t windowMs,
                                std::string_view message);

        std::unordered_map<std::string, std::deque<metricSample>> history_;
        std::vector<slopeRule> rules_;
    };
}