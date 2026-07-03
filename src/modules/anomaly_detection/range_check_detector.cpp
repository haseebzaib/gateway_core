#include "gateway/modules/anomaly_detection/range_check_detector.hpp"
#include "spdlog/spdlog.h"

namespace anomaly_detection
{

    rangeCheckDetector::rangeCheckDetector(std::vector<rangeRule> rules) : rules_(std::move(rules))
    {
    }

    std::string_view rangeCheckDetector::name() const
    {
        return "rangeCheckDetector";
    }

    std::vector<anomalyEvent> rangeCheckDetector::update(const metricSnapshot &snapshot)
    {
        std::vector<anomalyEvent> events;

        for (const metricSample& sample : snapshot.samples)
        {
            for (const rangeRule& rule : rules_)
            {
                if (rule.metricName != sample.name)
                {
                    continue;
                }

                bool rangeCheck = cross_range(sample.value, rule.minValue, rule.maxValue);

                if (rangeCheck)
                {
                    events.push_back(make_event(sample,
                                                rule.severity_,
                                                rule.minValue, rule.maxValue, rule.message));

                    SPDLOG_INFO("RangeDetector alert: severity={} metric={} value={} minValue={} maxValue={} timestamp_ms={} message={}",
                                sample.name,
                                sample.value,
                                rule.minValue,
                                rule.maxValue,
                                sample.timestamp_ms,
                                rule.message);
                }
                else
                {
                    events.push_back(make_event(sample,
                                                severity::Info,
                                                rule.minValue, rule.maxValue, "Normal"));
                }
            }
        }

        return events;
    }

    bool rangeCheckDetector::cross_range(double value, double minValue, double maxValue)
    {

        if (value < minValue || value > maxValue)
        {
            return true;
        }

        return false;
    }
    anomalyEvent rangeCheckDetector::make_event(const metricSample &sample, severity severity_, double minValue, double maxValue, std::string_view message)
    {
        return anomalyEvent{

            .detectorName = std::string{name()},
            .metricName = sample.name,
            .severity_ = severity_,
            .value = sample.value,
            .minValue = minValue,
            .maxValue = maxValue,
            .message = std::string{message},
            .timestamp_ms = sample.timestamp_ms

        };
    }

}