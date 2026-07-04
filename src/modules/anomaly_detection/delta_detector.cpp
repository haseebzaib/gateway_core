#include "gateway/modules/anomaly_detection/delta_detector.hpp"
#include "spdlog/spdlog.h"

namespace anomaly_detection
{
    deltaDetection::deltaDetection(std::vector<deltaRule> rules)
        : rules_(std::move(rules))
    {
    }

    std::string_view deltaDetection::name() const
    {
        return "deltaDetector";
    }

    std::vector<anomalyEvent> deltaDetection::update(const metricSnapshot& snapshot)
    {
        std::vector<anomalyEvent> events;

        for (const metricSample& sample : snapshot.samples)
        {
            for (const deltaRule& rule : rules_)
            {
                if (sample.name != rule.metricName)
                {
                    continue;
                }

                std::unordered_map<std::string, metricSample>::iterator it =
                    previousSamples_.find(rule.metricName);

                if (it == previousSamples_.end())
                {
                    previousSamples_[rule.metricName] = sample;

                    // events.push_back(make_event(sample,
                    //                             severity::Info,
                    //                             0.0,
                    //                             rule.warningDelta,
                    //                             rule.criticalDelta,
                    //                             rule.triggerPositive,
                    //                             "Delta warmup: first sample stored."));

                    continue;
                }

                const metricSample& previousSample = it->second;

                if (sample.timestamp_ms <= previousSample.timestamp_ms)
                {
                    previousSamples_[rule.metricName] = sample;

                    // events.push_back(make_event(sample,
                    //                             severity::Info,
                    //                             0.0,
                    //                             rule.warningDelta,
                    //                             rule.criticalDelta,
                    //                             rule.triggerPositive,
                    //                             "Delta reset: invalid or duplicate timestamp."));

                    continue;
                }

                std::uint64_t gapMs = sample.timestamp_ms - previousSample.timestamp_ms;

                if (rule.maxSampleGapMs > 0 && gapMs > rule.maxSampleGapMs)
                {
                    previousSamples_[rule.metricName] = sample;

                    // events.push_back(make_event(sample,
                    //                             severity::Info,
                    //                             0.0,
                    //                             rule.warningDelta,
                    //                             rule.criticalDelta,
                    //                             rule.triggerPositive,
                    //                             "Delta reset: sample gap too large."));

                    continue;
                }

                double delta = sample.value - previousSample.value;

                previousSamples_[rule.metricName] = sample;

                bool critical = false;
                bool warning = false;

                if (rule.triggerPositive)
                {
                    critical = delta >= rule.criticalDelta;
                    warning = delta >= rule.warningDelta;
                }
                else
                {
                    critical = delta <= -rule.criticalDelta;
                    warning = delta <= -rule.warningDelta;
                }

                if (critical)
                {
                    events.push_back(make_event(sample,
                                                severity::Critical,
                                                delta,
                                                rule.warningDelta,
                                                rule.criticalDelta,
                                                rule.triggerPositive,
                                                rule.message));
                }
                else if (warning)
                {
                    events.push_back(make_event(sample,
                                                severity::Warning,
                                                delta,
                                                rule.warningDelta,
                                                rule.criticalDelta,
                                                rule.triggerPositive,
                                                rule.message));
                }
                // else
                // {
                //     events.push_back(make_event(sample,
                //                                 severity::Info,
                //                                 delta,
                //                                 rule.warningDelta,
                //                                 rule.criticalDelta,
                //                                 rule.triggerPositive,
                //                                 "Delta is normal."));
                // }
            }
        }

        return events;
    }

    anomalyEvent deltaDetection::make_event(const metricSample& sample,
                                            severity severity_,
                                            double delta,
                                            double warningDelta,
                                            double criticalDelta,
                                            bool triggerPositive,
                                            std::string_view message)
    {
        return anomalyEvent{
            .detectorName = std::string{name()},
            .metricName = sample.name,
            .severity_ = severity_,
            .value = delta,
            .warningDelta = warningDelta,
            .criticalDelta = criticalDelta,
            .triggerPositive = triggerPositive,
            .message = std::string{message},
            .timestamp_ms = sample.timestamp_ms
        };
    }
}