#pragma once 

#include "cstdint"
#include "string"
#include "vector"


namespace anomaly_detection {


    enum class severity {

        Info,
        Warning,
        Critical
    };

    struct anomalyEvent {

        std::string detectorName;
        std::string metricName;
        severity severity_;
        double value;
        double criticalLimit;
        double warningLimit;
        double minValue;
        double maxValue;
        double warningDelta;
        double criticalDelta;
        double warningSlopePerMin;
        double criticalSlopePerMin;
        bool triggerPositive;
        std::uint64_t slopeWindowMs;
        std::uint64_t timeoutMs;
        std::string message;
        std::uint64_t timestamp_ms;
    };




}