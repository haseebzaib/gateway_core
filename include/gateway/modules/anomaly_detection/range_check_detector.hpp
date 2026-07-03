#pragma once 

#include <cstdint>
#include <string>
#include <vector>
#include <variant>
#include "utility"
#include "gateway/modules/anomaly_detection/metric.hpp"
#include "gateway/modules/anomaly_detection/event.hpp"
#include "gateway/modules/anomaly_detection/detector.hpp"



namespace anomaly_detection
{

    struct rangeRule {

        std::string metricName;
        double minValue;
        double maxValue;
        severity severity_;
        std::string message;
    };

    class rangeCheckDetector : public baseDetector
    {
        public:
        explicit rangeCheckDetector(std::vector<rangeRule> rules);
        std::string_view name() const override;
        std::vector<anomalyEvent> update(const metricSnapshot &snapshot) override;

        private:

        bool cross_range(double value, double minValue,double maxValue);
        anomalyEvent make_event(const metricSample& sample,severity severity_,double minValue,double maxValue,std::string_view message);

        std::vector<rangeRule> rules_;


    };


    


}