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
        severity severity;
        double value;
        double limit;
        std::string message;
        std::uint64_t timestamp_ms;
    };




}