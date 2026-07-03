#include "gateway/modules/anomaly_detection/threshold_detector.hpp"
#include "spdlog/spdlog.h"

namespace anomaly_detection
{

    thresholdDetector::thresholdDetector(std::vector<thresholdRule> rules)
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

        for (const metricSample& sample : snapshot.samples)
        {
            for (const thresholdRule& rule : rules_)
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
                                                rule.criticalLimit, rule.warningLimit, rule.message));

                    SPDLOG_INFO("Threshold alert: severity=Critical metric={} value={} limit={} trigger={} timestamp_ms={} message={}",
                                sample.name,
                                sample.value,
                                rule.criticalLimit,
                                rule.triggerAbove ? "above" : "below",
                                sample.timestamp_ms,
                                rule.message);
                }
                else if (warning)
                {
                    events.push_back(make_event(sample,
                                                severity::Warning, rule.criticalLimit,
                                                rule.warningLimit, rule.message));

                    SPDLOG_INFO("Threshold alert: severity=warning metric={} value={} limit={} trigger={} timestamp_ms={} message={}",
                                sample.name,
                                sample.value,
                                rule.warningLimit,
                                rule.triggerAbove ? "above" : "below",
                                sample.timestamp_ms,
                                rule.message);
                }
                else
                {
                    events.push_back(make_event(sample,
                                                severity::Info,
                                                rule.criticalLimit,
                                                rule.warningLimit, "normal"));

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

    anomalyEvent thresholdDetector::make_event(const metricSample &sample, severity severity_, double criticalLimit, double warningLimit, std::string_view message)
    {

        return anomalyEvent{

            .detectorName = std::string{name()},
            .metricName = sample.name,
            .severity_ = severity_,
            .value = sample.value,
            .criticalLimit = criticalLimit,
            .warningLimit = warningLimit,
            .message = std::string{message},
            .timestamp_ms = sample.timestamp_ms

        };
    }

}