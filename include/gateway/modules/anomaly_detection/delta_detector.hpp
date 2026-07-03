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


struct deltaRule
{
    std::string metricName;

    double warningDelta;
    double criticalDelta;

    bool triggerPositive;
    std::uint64_t maxSampleGapMs;

    std::string message;
};


    class deltaDetection : public baseDetector 
    {
        public:
        explicit deltaDetection(std::vector<deltaRule> rules);
        std::string_view name() const override;
        std::vector<anomalyEvent> update(const metricSnapshot &snapshot) override;

    private:
       
   anomalyEvent make_event(const metricSample& sample,
                            severity severity_,
                            double delta,
                            double warningDelta,
                            double criticalDelta,
                            bool triggerPositive,
                            std::string_view message);

    std::unordered_map<std::string, metricSample> previousSamples_;
    std::vector<deltaRule> rules_;

    };



}