#pragma once 

#include <cstdint>
#include <string>
#include <vector>
#include <variant>


namespace anomaly_detection {

    enum class metricType {
        Gauge, //normal values that goes up and down
        Counter, //values that usually increases
        Flag   //bit status flags
    };


    struct metricSample {
        std::string name;
        double value;
        std::uint64_t timestamp_ms;
        metricType type;
    };


    struct metricSnapshot {
        std::uint64_t timestamp_ms;
        std::vector<metricSample> samples;
    };



}