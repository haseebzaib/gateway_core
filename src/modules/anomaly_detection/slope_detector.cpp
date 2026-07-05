#include "gateway/modules/anomaly_detection/slope_detector.hpp"

#include "spdlog/spdlog.h"

namespace anomaly_detection
{
    slopeDetection::slopeDetection(std::vector<slopeRule> rules)
        : rules_(std::move(rules))
    {
        for (const slopeRule& rule : rules_)
        {
            history_.emplace(rule.metricName, std::deque<metricSample>{});
        }
    }

    std::string_view slopeDetection::name() const
    {
        return "slopeDetector";
    }

    std::vector<anomalyEvent> slopeDetection::update(const metricSnapshot& snapshot)
    {
        std::vector<anomalyEvent> events;

        for (const metricSample& sample : snapshot.samples)
        {
            for (const slopeRule& rule : rules_)
            {
                if (sample.name != rule.metricName)
                {
                    continue;
                }

                std::deque<metricSample>& history = history_[sample.name];

                /*
                 * Broken history protection:
                 *
                 * If previous sample exists and current sample is too far away
                 * from previous sample, old history is not trustworthy anymore.
                 */
                if (!history.empty())
                {
                    const metricSample& previousSample = history.back();

                    if (sample.timestamp_ms > previousSample.timestamp_ms)
                    {
                        std::uint64_t gapMs = sample.timestamp_ms - previousSample.timestamp_ms;

                        if (rule.maxSampleGapMs > 0 && gapMs > rule.maxSampleGapMs)
                        {
                            history.clear();
                        }
                    }
                    else
                    {
                        /*
                         * Time went backwards or duplicate/invalid timestamp.
                         * Reset history to avoid bad slope calculation.
                         */
                        history.clear();
                    }
                }

                history.push_back(sample);

                /*
                 * Keep only samples inside configured slope window.
                 */
                while (!history.empty() &&
                       sample.timestamp_ms >= history.front().timestamp_ms &&
                       sample.timestamp_ms - history.front().timestamp_ms > rule.windowMs)
                {
                    history.pop_front();
                }

                /*
                 * Warmup stage:
                 * Not enough samples yet, so generate Info if you want DB visibility.
                 */
                if (history.size() < rule.minSamples)
                {
                    // events.push_back(make_event(sample,
                    //                             severity::Info,
                    //                             0.0,
                    //                             rule.warningSlopePerMin,
                    //                             rule.criticalSlopePerMin,
                    //                             rule.triggerPositive,
                    //                             rule.windowMs,
                    //                             "Slope warmup: waiting for minimum samples."));

                    continue;
                }

                const metricSample& first = history.front();
                const metricSample& last = history.back();

                if (last.timestamp_ms <= first.timestamp_ms)
                {
                    // events.push_back(make_event(sample,
                    //                             severity::Info,
                    //                             0.0,
                    //                             rule.warningSlopePerMin,
                    //                             rule.criticalSlopePerMin,
                    //                             rule.triggerPositive,
                    //                             rule.windowMs,
                    //                             "Slope not evaluated: invalid or duplicate timestamps."));

                    continue;
                }

                std::uint64_t elapsedMs = last.timestamp_ms - first.timestamp_ms;

                /*
                 * Warmup stage:
                 * Enough samples maybe, but not enough time passed.
                 */
                if (elapsedMs < rule.minElapsedMs)
                {
                    // events.push_back(make_event(sample,
                    //                             severity::Info,
                    //                             0.0,
                    //                             rule.warningSlopePerMin,
                    //                             rule.criticalSlopePerMin,
                    //                             rule.triggerPositive,
                    //                             rule.windowMs,
                    //                             "Slope warmup: waiting for minimum elapsed time."));

                    continue;
                }

                double elapsedMin = static_cast<double>(elapsedMs) / 60000.0;

                if (elapsedMin <= 0.0)
                {
                    // events.push_back(make_event(sample,
                    //                             severity::Info,
                    //                             0.0,
                    //                             rule.warningSlopePerMin,
                    //                             rule.criticalSlopePerMin,
                    //                             rule.triggerPositive,
                    //                             rule.windowMs,
                    //                             "Slope not evaluated: elapsed time is zero."));

                    continue;
                }

                double slopePerMin = (last.value - first.value) / elapsedMin;

                bool critical = false;
                bool warning = false;

                if (rule.triggerPositive)
                {
                    critical = slopePerMin > rule.criticalSlopePerMin;
                    warning = slopePerMin > rule.warningSlopePerMin;
                }
                else
                {
                    critical = slopePerMin < -rule.criticalSlopePerMin;
                    warning = slopePerMin < -rule.warningSlopePerMin;
                }

                if (critical)
                {
                    events.push_back(make_event(sample,
                                                severity::Critical,
                                                slopePerMin,
                                                rule.warningSlopePerMin,
                                                rule.criticalSlopePerMin,
                                                rule.triggerPositive,
                                                rule.windowMs,
                                                rule.message));
                }
                else if (warning)
                {
                    events.push_back(make_event(sample,
                                                severity::Warning,
                                                slopePerMin,
                                                rule.warningSlopePerMin,
                                                rule.criticalSlopePerMin,
                                                rule.triggerPositive,
                                                rule.windowMs,
                                                rule.message));
                }
                else
                {
                    // events.push_back(make_event(sample,
                    //                             severity::Info,
                    //                             slopePerMin,
                    //                             rule.warningSlopePerMin,
                    //                             rule.criticalSlopePerMin,
                    //                             rule.triggerPositive,
                    //                             rule.windowMs,
                    //                             "Slope is normal."));
                }
            }
        }

        return events;
    }

    anomalyEvent slopeDetection::make_event(const metricSample& sample,
                                            severity severity_,
                                            double slopePerMin,
                                            double warningSlopePerMin,
                                            double criticalSlopePerMin,
                                            bool triggerPositive,
                                            std::uint64_t windowMs,
                                            std::string_view message)
    {
        return anomalyEvent{
            .detectorName = std::string{name()},
            .metricName = sample.name,
            .severity_ = severity_,
            .value = sample.value,
            .slopeValue = slopePerMin,
            .warningSlopePerMin = warningSlopePerMin,
            .criticalSlopePerMin = criticalSlopePerMin,
            .triggerPositive = triggerPositive,
            .slopeWindowMs = windowMs,
            .message = std::string{message},
            .timestamp_ms = sample.timestamp_ms
        };
    }
}