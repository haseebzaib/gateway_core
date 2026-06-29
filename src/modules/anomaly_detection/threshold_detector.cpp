#include "gateway/modules/anomaly_detection/threshold_detector.hpp"

namespace anomaly_detection
{

    explicit thresholdDetector::thresholdDetector(std::vector<thresholdRule> rules)
        : rules_(std::move(rules))
    {
    }

    std::string_view thresholdDetector::name() const
    {
        return "thresholdDetector";
    }

    std::vector<anomalyEvent> thresholdDetector::update(const metricSnapshot &snapshot)
    {
        std::vector<anomalyEvent> events;

        for (const metricSample sample : snapshot.samples)
        {
            for (const thresholdRule rule : rules_)
            {

                if (sample.name != rule.metricName)
                {
                    continue;
                }

                bool critical = cross_limit(sample.value, rule.criticalLimit, rule.triggerAbove);
                bool warning = cross_limit(sample.value, rule.warningLimit, rule.triggerAbove);

                if (critical)
                {
                    events.push_back(make_event(sample,
                                               severity::Critical,
                                               rule.criticalLimit,rule.message));
                }
                else if (warning)
                {
                    events.push_back(make_event(sample,
                                               severity::Warning,
                                               rule.warningLimit,rule.message));
                }
            }
        }

        return events;
    }

    bool thresholdDetector::cross_limit(double value, double limit, bool triggerAbove)
    {
        if (triggerAbove)
        {
            return value > limit;
        }
        return value < limit;
    }

    anomalyEvent thresholdDetector::make_event(const metricSample &sample, severity severity_, double limit, std::string_view message)
    {

        return anomalyEvent{

            .detectorName = std::string{name()},
            .metricName = sample.name,
            .severity = severity_,
            .value = sample.value,
            .limit = limit,
            .message = std::string{message},
            .timestamp_ms = sample.timestamp_ms

        };
    }

}