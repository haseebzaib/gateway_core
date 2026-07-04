#include "gateway/modules/anomaly_detection/timeout_detector.hpp"
#include "spdlog/spdlog.h"

namespace anomaly_detection
{
    timeoutDetector::timeoutDetector(std::vector<timeoutRule> rules)
        : rules_(std::move(rules))
    {
    }

    std::string_view timeoutDetector::name() const
    {
        return "TimeoutDetector";
    }

    std::vector<anomalyEvent> timeoutDetector::update(const metricSnapshot& snapshot)
    {
        std::vector<anomalyEvent> events;

        /*
         * Step 1:
         * Any metric present in this snapshot is considered seen.
         */
        for (const metricSample& sample : snapshot.samples)
        {
            lastSeenTimestampMs_[sample.name] = sample.timestamp_ms;
        }

        /*
         * Step 2:
         * Check timeout rules.
         */
        for (const timeoutRule& rule : rules_)
        {
            std::unordered_map<std::string, std::uint64_t>::const_iterator it =
                lastSeenTimestampMs_.find(rule.metricName);

            /*
             * Metric has never been seen yet.
             * At startup, do not alarm immediately.
             */
            if (it == lastSeenTimestampMs_.end())
            {
                continue;
            }

            std::uint64_t lastSeen = it->second;

            if (snapshot.timestamp_ms < lastSeen)
            {
                /*
                 * Timestamp went backwards.
                 * Ignore this cycle.
                 */
                continue;
            }

            std::uint64_t elapsedMs = snapshot.timestamp_ms - lastSeen;

            if (elapsedMs > rule.timeoutMs)
            {
                events.push_back(make_event(rule.metricName,
                                            snapshot.timestamp_ms,
                                            rule.severity_,
                                            rule.timeoutMs,
                                            rule.message));
            }
        }

        return events;
    }

    anomalyEvent timeoutDetector::make_event(std::string_view metricName,
                                             std::uint64_t timestampMs,
                                             severity severity_,
                                             std::uint64_t timeoutMs,
                                             std::string_view message)
    {
        return anomalyEvent{
            .detectorName = std::string{name()},
            .metricName = std::string{metricName},
            .severity_ = severity_,
            .value = 0.0,
            .timeoutMs = timeoutMs,
            .message = std::string{message},
            .timestamp_ms = timestampMs
        };
    }
}