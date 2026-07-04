#include "gateway/modules/anomaly_detection/timeout_detector.hpp"
#include "spdlog/spdlog.h"

namespace anomaly_detection
{

    timeoutDetector::timeoutDetector(std::vector<timeoutRule> rules) : rules_(std::move(rules))
    {
        for (const timeoutRule &rule : rules_)
        {
            previousValue.emplace(rule.metricName, 0);
            lastSeenTimestampMs_.emplace(rule.metricName, 0);
        }
    }
    std::string_view timeoutDetector::name() const
    {

        return "timeoutDetector";
    }
    std::vector<anomalyEvent> timeoutDetector::update(const metricSnapshot &snapshot)
    {
        std::vector<anomalyEvent> events;

        for (const metricSample& sample : snapshot.samples)
        {
            for (const timeoutRule& rule : rules_)
            {
                if (sample.name != rule.metricName)
                {
                    continue;
                }

                if (sample.value != previousValue[rule.metricName])
                {
                    previousValue.emplace(rule.metricName, sample.value);
                    lastSeenTimestampMs_.emplace(rule.metricName, sample.timestamp_ms);
                }

                if (sample.timestamp_ms - lastSeenTimestampMs_[rule.metricName] > rule.timeoutMS)
                {

                    events.push_back(make_event(sample,rule.severity_,rule.timeoutMS,rule.message));
                }
                // else
                // {
                //     events.push_back(make_event(sample,severity::Info,rule.timeoutMS,"Normal"));
                // }
            }
        }

        return events;
    }

    anomalyEvent timeoutDetector::make_event(const metricSample &sample, severity severity_,
                                             std::uint64_t timeoutMs, std::string_view message)
    {
        return anomalyEvent{

            .detectorName = std::string{name()},
            .metricName = sample.name,
            .severity_ = severity_,
            .value = sample.value,
            .timeoutMs = timeoutMs,
            .message = std::string{message},
            .timestamp_ms = sample.timestamp_ms
        };
    }

}
