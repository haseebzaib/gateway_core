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

                std::deque<double>& window = stats_[rule.metricName].window;

                // Advances the rolling window with the current value; called on
                // every path so the baseline always keeps up with the metric.
                const auto advance = [&]()
                {
                    window.push_back(sample.value);
                    while (window.size() > rule.warmupSamples)
                    {
                        window.pop_front();
                    }
                };

                /*
                 * Warmup:
                 * Build a full baseline window before evaluating anything.
                 */
                if (window.size() < rule.warmupSamples)
                {
                    window.push_back(sample.value);
                    continue;
                }

                // Baseline mean + std-dev over the recent window (excludes the
                // current sample, so an abnormal value can't hide itself).
                double sum = 0.0;
                for (double value : window)
                {
                    sum += value;
                }
                const double mean = sum / static_cast<double>(window.size());

                double sqSum = 0.0;
                for (double value : window)
                {
                    const double d = value - mean;
                    sqSum += d * d;
                }
                const double variance = sqSum / static_cast<double>(window.size() - 1);
                const double currentStdDev = (variance > 0.0) ? std::sqrt(variance) : 0.0;

                /*
                 * If stddev is too small the metric is essentially flat, so a
                 * z-score is meaningless (a tiny quantized step would explode).
                 */
                if (currentStdDev < rule.minStdDev)
                {
                    advance();
                    continue;
                }

                const double zScore = (sample.value - mean) / currentStdDev;
                const double absZScore = std::fabs(zScore);

                // Also require a real absolute gap from the baseline, so tiny
                // wobbles around a low idle value can't look "unusual" just
                // because the baseline variation is small.
                const double absDelta = std::fabs(sample.value - mean);
                const bool farEnough = absDelta >= rule.minAbsDelta;

                const bool critical = farEnough && absZScore >= rule.criticalZ;
                const bool warning = farEnough && absZScore >= rule.warningZ;

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

                advance();
            }
        }

        return events;
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
            .value = sample.value,
            .zScore = zScore,
            .warningZ = warningZ,
            .criticalZ = criticalZ,
            .message = std::string{message},
            .timestamp_ms = sample.timestamp_ms
        };
    }
}