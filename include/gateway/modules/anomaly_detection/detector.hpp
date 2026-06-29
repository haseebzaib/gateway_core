#pragma once

#include "gateway/modules/anomaly_detection/metric.hpp"
#include "gateway/modules/anomaly_detection/event.hpp"
#include "string_view"
#include "vector"

namespace anomaly_detection
{

    class baseDetector
    {
    public:
        virtual ~baseDetector() = default;

        virtual std::string_view name() const = 0;
        virtual std::vector<anomalyEvent> update(const metricSnapshot &snapshot) = 0;
    };

}