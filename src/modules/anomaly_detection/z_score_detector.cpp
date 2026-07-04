#include "gateway/modules/anomaly_detection/z_score_detector.hpp"

#include <cmath>
#include <utility>

namespace anomaly_detection
{
    zScoreDetection::zScoreDetection(std::vector<zScoreRule> rules)
        : rules_(std::move(rules))
    {
    }

    std::string_view zScoreDetection::name() const
    {
        return "ZScoreDetector";
    }

    std::vector<anomalyEvent> zScoreDetection::update(const metricSnapshot& snapshot)
    {
        std::vector<anomalyEvent> events;

        for (const metricSample& sample : snapshot.samples)
        {
            for (const zScoreRule& rule : rules_)
            {
                if (sample.name != rule.metricName)
                {
                    continue;
                }

                runningStats& stats = stats_[rule.metricName];

                /*
                 * Warmup:
                 * First samples are only used to build baseline.
                 * No Info event, no Warning, no Critical.
                 */
                if (stats.count < rule.warmupSamples)
                {
                    update_stats(stats, sample.value);
                    continue;
                }

                double currentStdDev = stddev(stats);

                /*
                 * If stddev is too small, z-score is not reliable.
                 * Still update baseline, but do not generate alarm.
                 */
                if (currentStdDev < rule.minStdDev)
                {
                    update_stats(stats, sample.value);
                    continue;
                }

                /*
                 * Calculate z-score using old stats first.
                 * Then update stats after evaluation.
                 *
                 * This is important:
                 * current abnormal value should not hide itself by updating mean first.
                 */
                double zScore = (sample.value - stats.mean) / currentStdDev;

                double absZScore = std::fabs(zScore);

                bool critical = absZScore >= rule.criticalZ;
                bool warning = absZScore >= rule.warningZ;

                if (critical)
                {
                    events.push_back(make_event(sample,
                                                severity::Critical,
                                                zScore,
                                                rule.warningZ,
                                                rule.criticalZ,
                                                rule.message));
                }
                else if (warning)
                {
                    events.push_back(make_event(sample,
                                                severity::Warning,
                                                zScore,
                                                rule.warningZ,
                                                rule.criticalZ,
                                                rule.message));
                }

                /*
                 * Always update stats after evaluation.
                 *
                 * Later, if you do not want anomalies to affect baseline,
                 * you can choose to update only when not warning/critical.
                 */
                update_stats(stats, sample.value);
            }
        }

        return events;
    }

    void zScoreDetection::update_stats(runningStats& stats, double value)
    {
        /*
         * Welford online algorithm.
         *
         * It updates mean and variance without storing all old samples.
         */
        stats.count++;

        double delta = value - stats.mean;
        stats.mean += delta / static_cast<double>(stats.count);

        double delta2 = value - stats.mean;
        stats.m2 += delta * delta2;
    }

    double zScoreDetection::stddev(const runningStats& stats) const
    {
        if (stats.count < 2)
        {
            return 0.0;
        }

        double variance = stats.m2 / static_cast<double>(stats.count - 1);

        if (variance <= 0.0)
        {
            return 0.0;
        }

        return std::sqrt(variance);
    }

    anomalyEvent zScoreDetection::make_event(const metricSample& sample,
                                             severity severity_,
                                             double zScore,
                                             double warningZ,
                                             double criticalZ,
                                             std::string_view message)
    {
        return anomalyEvent{
            .detectorName = std::string{name()},
            .metricName = sample.name,
            .severity_ = severity_,
            .value = zScore,
            .warningZ = warningZ,
            .criticalZ = criticalZ,
            .message = std::string{message},
            .timestamp_ms = sample.timestamp_ms
        };
    }
}