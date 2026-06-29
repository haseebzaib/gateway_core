#pragma once

#include "gateway/modules/anomaly_detection/metric.hpp"
#include "gateway/modules/anomaly_detection/event.hpp"
#include "gateway/modules/anomaly_detection/detector.hpp"
#include "string"
#include "vector"
#include "utility"

namespace anomaly_detection
{

    struct thresholdRule
    {
        std::string metricName;
        double warningLimit;
        double criticalLimit;
        bool triggerAbove;
        std::string message;
    };

    class thresholdDetector : public baseDetector
    {

    public:
        explicit thresholdDetector(std::vector<thresholdRule> rules);
        std::string_view name() const override;

        std::vector<anomalyEvent> update(const metricSnapshot &snapshot) override;

    private:

    bool cross_limit(double value,double limit,bool triggerAbove);
    anomalyEvent make_event(const metricSample& sample,severity severity_,double limit,std::string_view message);
    std::vector<thresholdRule> rules_;
    };

}
