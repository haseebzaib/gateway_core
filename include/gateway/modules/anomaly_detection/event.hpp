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
        double value; // always the raw metric reading (sample.value)
        // Actual measured derived quantities, kept separate from the
        // warning/critical *thresholds* below. Only set by the matching
        // detector; left 0 otherwise. Never overload `value` with these.
        double zScore;     // z-score detector: std-devs from the learned mean
        double deltaValue; // delta detector: change vs the previous sample
        double slopeValue; // slope detector: rate of change per minute
        double criticalLimit;
        double warningLimit;
        double minValue;
        double maxValue;
        double warningDelta;
        double criticalDelta;
        double warningSlopePerMin;
        double criticalSlopePerMin;
        bool triggerPositive;
        std::string alarmName;
        double warningZ;
        double criticalZ;
        std::uint64_t slopeWindowMs;
        std::uint64_t timeoutMs;
        std::string message;
        std::uint64_t timestamp_ms;
    };




}