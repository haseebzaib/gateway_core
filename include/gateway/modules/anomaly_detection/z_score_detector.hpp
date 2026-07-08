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
    struct zScoreRule
    {
        std::string metricName;

        double warningZ;
        double criticalZ;

        /*
         * Number of samples needed before z-score evaluation starts.
         * Until this count is reached, detector only learns baseline.
         */
        std::size_t warmupSamples;

        /*
         * If standard deviation is too small, z-score can explode.
         * Example:
         * mean = 50
         * stddev = 0.0001
         * current = 51
         *
         * z becomes huge, even though value is not really dangerous.
         */
        double minStdDev;

        std::string message;
    };

    class zScoreDetection : public baseDetector
    {
    public:
        explicit zScoreDetection(std::vector<zScoreRule> rules);

        std::string_view name() const override;

        std::vector<anomalyEvent> update(const metricSnapshot& snapshot) override;

    private:
        // Rolling window of recent values (the last `warmupSamples`), so the
        // baseline forgets old data. A step change is thus forgotten after
        // ~one window instead of firing forever, and a flat line has ~zero
        // std-dev so it can never look "unusual".
        struct runningStats
        {
            std::deque<double> window;
        };

        anomalyEvent make_event(const metricSample& sample,
                                severity severity_,
                                double zScore,
                                double warningZ,
                                double criticalZ,
                                std::string_view message);

        std::unordered_map<std::string, runningStats> stats_;
        std::vector<zScoreRule> rules_;
    };
}