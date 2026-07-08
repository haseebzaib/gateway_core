#include "gateway/core/deviceprocess.hpp"
#include "gateway/core/interprocess.hpp"
#include "gateway/modules/message_protocol/message_protocol.hpp"
#include "gateway/modules/anomaly_detection/detector.hpp"
#include "gateway/modules/anomaly_detection/delta_detector.hpp"
#include "gateway/modules/anomaly_detection/multi_condition_detector.hpp"
#include "gateway/modules/anomaly_detection/range_check_detector.hpp"
#include "gateway/modules/anomaly_detection/slope_detector.hpp"
#include "gateway/modules/anomaly_detection/threshold_detector.hpp"
#include "gateway/modules/anomaly_detection/timeout_detector.hpp"
#include "gateway/modules/anomaly_detection/z_score_detector.hpp"

#include "thread"
#include "chrono"
#include "spdlog/spdlog.h"
#include "spdlog/fmt/fmt.h"

#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sys/statvfs.h>

namespace core::deviceprocess
{

    namespace
    {
        using deviceMetrics = module::message_protocol::messageProtocol::deviceMetrics;

        constexpr int kSampleIntervalMs = 1000; // how often we sample + send
        constexpr int kEmmcLifeEveryN = 2500;   // refresh slow eMMC-life read every N cycles

        std::vector<anomaly_detection::thresholdRule> thresholdRules;
        std::vector<anomaly_detection::rangeRule> rangeRules;
        std::vector<anomaly_detection::deltaRule> deltaRules;
        std::vector<anomaly_detection::slopeRule> slopeRules;
        std::vector<anomaly_detection::zScoreRule> zScoreRules;
        std::vector<anomaly_detection::timeoutRule> timeoutRules;
        std::vector<anomaly_detection::multiConditionRule> multiConditionRules;
        std::vector<std::unique_ptr<anomaly_detection::baseDetector>> anomalyDetectors;
        anomaly_detection::metricSnapshot deviceMetricsSnapshot;

        std::string_view severity_text(anomaly_detection::severity severity)
        {
            switch (severity)
            {
            case anomaly_detection::severity::Info:
                return "Info";
            case anomaly_detection::severity::Warning:
                return "Warning";
            case anomaly_detection::severity::Critical:
                return "Critical";
            }

            return "Unknown";
        }

        void threshold_rule_creator(std::string_view metricName, double warningLimit, double criticalLimit, bool triggerAbove, std::string_view message)
        {
            thresholdRules.push_back(anomaly_detection::thresholdRule{
                .metricName = std::string{metricName},
                .warningLimit = warningLimit,
                .criticalLimit = criticalLimit,
                .triggerAbove = triggerAbove,
                .message = std::string{message}});
        }

        void range_rule_creator(std::string_view metricName,
                                double minValue,
                                double maxValue,
                                anomaly_detection::severity severity,
                                std::string_view message)
        {
            rangeRules.push_back(anomaly_detection::rangeRule{
                .metricName = std::string{metricName},
                .minValue = minValue,
                .maxValue = maxValue,
                .severity_ = severity,
                .message = std::string{message}});
        }

        void delta_rule_creator(std::string_view metricName,
                                double warningDelta,
                                double criticalDelta,
                                bool triggerPositive,
                                std::uint64_t maxSampleGapMs,
                                std::string_view message)
        {
            deltaRules.push_back(anomaly_detection::deltaRule{
                .metricName = std::string{metricName},
                .warningDelta = warningDelta,
                .criticalDelta = criticalDelta,
                .triggerPositive = triggerPositive,
                .maxSampleGapMs = maxSampleGapMs,
                .message = std::string{message}});
        }

        void slope_rule_creator(std::string_view metricName,
                                double warningSlopePerMin,
                                double criticalSlopePerMin,
                                std::uint64_t minElapsedMs,
                                std::size_t minSamples,
                                bool triggerPositive,
                                std::uint64_t windowMs,
                                std::uint64_t maxSampleGapMs,
                                std::string_view message)
        {
            slopeRules.push_back(anomaly_detection::slopeRule{
                .metricName = std::string{metricName},
                .warningSlopePerMin = warningSlopePerMin,
                .criticalSlopePerMin = criticalSlopePerMin,
                .minElapsedMs = minElapsedMs,
                .minSamples = minSamples,
                .triggerPositive = triggerPositive,
                .windowMs = windowMs,
                .maxSampleGapMs = maxSampleGapMs,
                .message = std::string{message}});
        }

        void z_score_rule_creator(std::string_view metricName,
                                  double warningZ,
                                  double criticalZ,
                                  std::size_t warmupSamples,
                                  double minStdDev,
                                  std::string_view message)
        {
            zScoreRules.push_back(anomaly_detection::zScoreRule{
                .metricName = std::string{metricName},
                .warningZ = warningZ,
                .criticalZ = criticalZ,
                .warmupSamples = warmupSamples,
                .minStdDev = minStdDev,
                .message = std::string{message}});
        }

        void timeout_rule_creator(std::string_view metricName,
                                  std::uint64_t timeoutMs,
                                  anomaly_detection::severity severity,
                                  std::string_view message)
        {
            timeoutRules.push_back(anomaly_detection::timeoutRule{
                .metricName = std::string{metricName},
                .timeoutMs = timeoutMs,
                .severity_ = severity,
                .message = std::string{message}});
        }

        void multi_condition_rule_creator(std::string_view alarmName,
                                          std::vector<anomaly_detection::condition> conditions,
                                          anomaly_detection::logicOp logic,
                                          anomaly_detection::severity severity,
                                          std::string_view message)
        {
            multiConditionRules.push_back(anomaly_detection::multiConditionRule{
                .alarmName = std::string{alarmName},
                .conditions = std::move(conditions),
                .logic = logic,
                .severity_ = severity,
                .message = std::string{message}});
        }

        void make_threshold_rule_creator()
        {
            thresholdRules.clear();
            /*
             * CPU usage
             * High CPU for a short time is normal.
             * Threshold detector should ideally have debounce/duration later.
             */
            threshold_rule_creator(
                "cpu.usage",
                85.0,
                95.0,
                true,
                "CPU usage is high. Check for stuck process, infinite loop, heavy task, or unexpected background load.");

            /*
             * CPU temperature
             * These are reasonable generic embedded Linux limits.
             * Tune per board after testing.
             */
            threshold_rule_creator(
                "cpu.temp",
                75.0,
                85.0,
                true,
                "CPU temperature is high. Check enclosure airflow, heatsink contact, ambient temperature, and CPU load.");

            /*
             * Load average is normalized by online core count in the snapshot.
             * 1.0 means the CPU set is fully loaded; >1.0 means runnable work is queuing.
             */
            threshold_rule_creator(
                "cpu.load_1m",
                0.9,
                1.5,
                true,
                "1-minute normalized system load is high. Device may be overloaded; check CPU-heavy tasks or blocked processes.");

            threshold_rule_creator(
                "cpu.load_5m",
                0.9,
                1.5,
                true,
                "5-minute normalized system load is high. Load is sustained; check long-running CPU or I/O bound tasks.");

            threshold_rule_creator(
                "cpu.load_15m",
                0.9,
                1.5,
                true,
                "15-minute normalized system load is high. Device has been overloaded for a long time; investigate services and logs.");

            /*
             * Raspberry Pi throttling flags.
             * 0 means no throttling flag.
             * Anything above 0 means some throttling/undervoltage event is present.
             */
            threshold_rule_creator(
                "cpu.throttle_flags",
                0.0,
                1.0,
                true,
                "CPU throttling or undervoltage flag detected. Check power supply, thermal throttling, and board cooling.");

            /*
             * RAM used percentage.
             * Better than raw MB because devices may have different RAM sizes.
             */
            threshold_rule_creator(
                "memory.ram_used_pct",
                80.0,
                90.0,
                true,
                "RAM usage is high. Check memory leak, heavy process, cache growth, or reduce running services.");

            /*
             * Swap usage.
             * Any swap usage is not always bad, but high swap on embedded devices can mean memory pressure.
             * If your device normally never swaps, lower these values.
             */
            threshold_rule_creator(
                "memory.swap_used_mb",
                128.0,
                512.0,
                true,
                "Swap usage is high. Device may be under memory pressure; check RAM usage and possible memory leak.");

            /*
             * Disk usage.
             */
            threshold_rule_creator(
                "storage.disk_used_pct",
                80.0,
                90.0,
                true,
                "Disk usage is high. Clean old logs, rotate logs, remove temporary files, or increase storage.");

            threshold_rule_creator(
                "storage.emmc_used_pct",
                80.0,
                90.0,
                true,
                "eMMC/SD usage is high across mounted device partitions. Clean retained files or increase storage.");

            /*
             * eMMC life used.
             * This is wear indicator. It does not usually recover.
             */
            threshold_rule_creator(
                "storage.emmc_life_used_pct",
                70.0,
                90.0,
                true,
                "eMMC lifetime usage is high. Storage wear is increasing; reduce writes, check logging, and plan replacement.");

            /*
             * Uptime too low can indicate frequent reboot/crash loop.
             * triggerAbove = false means alert when value is below limit.
             *
             * This rule is useful only if checked after boot grace period.
             */
            threshold_rule_creator(
                "system.uptime_sec",
                300.0,
                60.0,
                false,
                "System uptime is very low. Device may have recently rebooted; check crash logs, watchdog, power loss, or kernel panic.");
        }

        void make_range_rule_creator()
        {
            rangeRules.clear();

            range_rule_creator("cpu.usage", 0.0, 100.0, anomaly_detection::severity::Critical,
                               "CPU usage reading is outside the valid 0-100% range. Check metric collection.");
            range_rule_creator("cpu.temp", -40.0, 95.0, anomaly_detection::severity::Critical,
                               "CPU temperature reading is outside expected device range. Check thermal sensor or board health.");
            range_rule_creator("cpu.core_count", 1.0, 64.0, anomaly_detection::severity::Critical,
                               "Online CPU core count is invalid. Check /proc/stat parsing or CPU hotplug state.");
            range_rule_creator("cpu.load_1m", 0.0, 32.0, anomaly_detection::severity::Warning,
                               "1-minute normalized load reading is outside expected range. Check load average collection.");
            range_rule_creator("cpu.load_5m", 0.0, 32.0, anomaly_detection::severity::Warning,
                               "5-minute normalized load reading is outside expected range. Check load average collection.");
            range_rule_creator("cpu.load_15m", 0.0, 32.0, anomaly_detection::severity::Warning,
                               "15-minute normalized load reading is outside expected range. Check load average collection.");
            range_rule_creator("cpu.throttle_flags", 0.0, 15.0, anomaly_detection::severity::Critical,
                               "CPU throttle flags are outside the valid Raspberry Pi live flag bit range.");
            range_rule_creator("memory.ram_used_mb", 0.0, 1048576.0, anomaly_detection::severity::Critical,
                               "RAM used reading is invalid. Check /proc/meminfo parsing.");
            range_rule_creator("memory.ram_total_mb", 1.0, 1048576.0, anomaly_detection::severity::Critical,
                               "RAM total reading is invalid. Check /proc/meminfo parsing.");
            range_rule_creator("memory.ram_used_pct", 0.0, 100.0, anomaly_detection::severity::Critical,
                               "RAM usage percent is outside the valid 0-100% range.");
            range_rule_creator("memory.swap_used_mb", 0.0, 1048576.0, anomaly_detection::severity::Critical,
                               "Swap usage reading is invalid. Check /proc/meminfo parsing.");
            range_rule_creator("storage.disk_used_pct", 0.0, 100.0, anomaly_detection::severity::Critical,
                               "Root disk usage percent is outside the valid 0-100% range.");
            range_rule_creator("storage.emmc_used_mb", 0.0, 104857600.0, anomaly_detection::severity::Critical,
                               "eMMC/SD used-space reading is invalid. Check mount parsing.");
            range_rule_creator("storage.emmc_total_mb", 0.0, 104857600.0, anomaly_detection::severity::Warning,
                               "eMMC/SD total-space reading is outside expected range. Device may not expose mmcblk0.");
            range_rule_creator("storage.emmc_used_pct", 0.0, 100.0, anomaly_detection::severity::Critical,
                               "eMMC/SD usage percent is outside the valid 0-100% range.");
            range_rule_creator("storage.emmc_life_used_pct", 0.0, 100.0, anomaly_detection::severity::Critical,
                               "eMMC life reading is outside the valid 0-100% range.");
            range_rule_creator("system.uptime_sec", 0.0, 315360000.0, anomaly_detection::severity::Critical,
                               "System uptime reading is invalid. Check /proc/uptime parsing.");
        }

        void make_delta_rule_creator()
        {
            deltaRules.clear();

            delta_rule_creator("cpu.usage", 50.0, 75.0, true, 5000,
                               "CPU usage jumped sharply between samples. Check for sudden workload spikes.");
            delta_rule_creator("cpu.temp", 8.0, 15.0, true, 5000,
                               "CPU temperature jumped sharply. Check fan/heatsink contact, enclosure airflow, or sudden CPU load.");
            delta_rule_creator("memory.ram_used_pct", 15.0, 25.0, true, 5000,
                               "RAM usage jumped sharply. Check for burst allocation or a memory leak.");
            delta_rule_creator("memory.swap_used_mb", 64.0, 256.0, true, 5000,
                               "Swap usage jumped sharply. Device may be entering memory pressure.");
            delta_rule_creator("storage.disk_used_pct", 2.0, 5.0, true, 5000,
                               "Root disk usage increased sharply. Check logs, captures, or temporary files.");
            delta_rule_creator("storage.emmc_used_pct", 2.0, 5.0, true, 5000,
                               "eMMC/SD usage increased sharply. Check retained data, logs, or buffers.");
        }

        void make_slope_rule_creator()
        {
            slopeRules.clear();

            slope_rule_creator("cpu.temp", 10.0, 20.0, 10000, 5, true, 60000, 5000,
                               "CPU temperature is rising quickly over the current window.");
            slope_rule_creator("memory.ram_used_pct", 10.0, 20.0, 10000, 5, true, 60000, 5000,
                               "RAM usage is rising quickly. Possible memory leak or runaway workload.");
            slope_rule_creator("memory.swap_used_mb", 128.0, 512.0, 10000, 5, true, 60000, 5000,
                               "Swap usage is rising quickly. Device may be under sustained memory pressure.");
            slope_rule_creator("storage.disk_used_pct", 1.0, 3.0, 10000, 5, true, 120000, 5000,
                               "Root disk usage is increasing quickly. Check logs, captures, or buffering.");
            slope_rule_creator("storage.emmc_used_pct", 1.0, 3.0, 10000, 5, true, 120000, 5000,
                               "eMMC/SD usage is increasing quickly. Check retained data, logs, or buffering.");
        }

        void make_z_score_rule_creator()
        {
            zScoreRules.clear();

            z_score_rule_creator("cpu.usage", 3.0, 5.0, 30, 2.0,
                                 "CPU usage is unusual compared with the learned device baseline.");
            z_score_rule_creator("cpu.temp", 3.0, 5.0, 30, 1.0,
                                 "CPU temperature is unusual compared with the learned device baseline.");
            z_score_rule_creator("cpu.load_1m", 3.0, 5.0, 30, 0.05,
                                 "1-minute normalized load is unusual compared with the learned device baseline.");
            z_score_rule_creator("memory.ram_used_pct", 3.0, 5.0, 30, 1.0,
                                 "RAM usage is unusual compared with the learned device baseline.");
            // Storage fills slowly and monotonically; it has no meaningful
            // "normal variation" to be unusual against, so require a full 1% of
            // real movement before z-score even considers it (otherwise tiny
            // quantized steps on an essentially flat line read as huge z-scores).
            z_score_rule_creator("storage.disk_used_pct", 3.0, 5.0, 30, 1.0,
                                 "Root disk usage is unusual compared with the learned device baseline.");
            z_score_rule_creator("storage.emmc_used_pct", 3.0, 5.0, 30, 1.0,
                                 "eMMC/SD usage is unusual compared with the learned device baseline.");
        }

        void make_timeout_rule_creator()
        {
            timeoutRules.clear();

            timeout_rule_creator("cpu.usage", 5000, anomaly_detection::severity::Critical,
                                 "CPU usage metric has not been observed recently.");
            timeout_rule_creator("cpu.temp", 5000, anomaly_detection::severity::Critical,
                                 "CPU temperature metric has not been observed recently.");
            timeout_rule_creator("cpu.load_1m", 5000, anomaly_detection::severity::Warning,
                                 "1-minute normalized load metric has not been observed recently.");
            timeout_rule_creator("memory.ram_used_pct", 5000, anomaly_detection::severity::Critical,
                                 "RAM usage percent metric has not been observed recently.");
            timeout_rule_creator("storage.disk_used_pct", 5000, anomaly_detection::severity::Critical,
                                 "Root disk usage metric has not been observed recently.");
            timeout_rule_creator("storage.emmc_used_pct", 5000, anomaly_detection::severity::Warning,
                                 "eMMC/SD usage percent metric has not been observed recently.");
            timeout_rule_creator("system.uptime_sec", 5000, anomaly_detection::severity::Critical,
                                 "System uptime metric has not been observed recently.");
        }

        void make_multi_condition_rule_creator()
        {
            using anomaly_detection::compareOp;
            using anomaly_detection::condition;
            using anomaly_detection::logicOp;
            using anomaly_detection::severity;

            multiConditionRules.clear();

            multi_condition_rule_creator(
                "device_thermal_stress",
                std::vector<condition>{
                    {.metricName = "cpu.usage", .op = compareOp::GreaterThan, .value = 85.0},
                    {.metricName = "cpu.temp", .op = compareOp::GreaterThan, .value = 75.0}},
                logicOp::All,
                severity::Warning,
                "CPU usage and temperature are both high. Device may be thermally stressed.");

            multi_condition_rule_creator(
                "device_throttling_thermal",
                std::vector<condition>{
                    {.metricName = "cpu.throttle_flags", .op = compareOp::GreaterThan, .value = 0.0},
                    {.metricName = "cpu.temp", .op = compareOp::GreaterThan, .value = 70.0}},
                logicOp::All,
                severity::Critical,
                "CPU throttling flags are active while temperature is high. Check cooling and power supply.");

            multi_condition_rule_creator(
                "device_memory_pressure",
                std::vector<condition>{
                    {.metricName = "memory.ram_used_pct", .op = compareOp::GreaterThan, .value = 85.0},
                    {.metricName = "memory.swap_used_mb", .op = compareOp::GreaterThan, .value = 128.0}},
                logicOp::All,
                severity::Critical,
                "RAM usage and swap usage are both high. Device is under memory pressure.");

            multi_condition_rule_creator(
                "device_storage_risk",
                std::vector<condition>{
                    {.metricName = "storage.disk_used_pct", .op = compareOp::GreaterThan, .value = 85.0},
                    {.metricName = "storage.emmc_life_used_pct", .op = compareOp::GreaterThan, .value = 70.0}},
                logicOp::All,
                severity::Warning,
                "Root storage is filling while eMMC life usage is high. Reduce writes and clean retained data.");

            multi_condition_rule_creator(
                "device_boot_under_load",
                std::vector<condition>{
                    {.metricName = "system.uptime_sec", .op = compareOp::LessThan, .value = 300.0},
                    {.metricName = "cpu.load_1m", .op = compareOp::GreaterThan, .value = 0.9}},
                logicOp::All,
                severity::Warning,
                "Device recently booted and is already under high load. Check startup services and crash loop risk.");
        }

        void add_metric(anomaly_detection::metricSnapshot &snapshot,
                        const std::string &name,
                        double value,
                        std::uint64_t timestamp_ms,
                        anomaly_detection::metricType type)
        {
            anomaly_detection::metricSample sample;

            sample.name = name;
            sample.value = value;
            sample.timestamp_ms = timestamp_ms;
            sample.type = type;

            snapshot.samples.push_back(sample);
        }

        void make_device_metric_snapshot(const deviceMetrics &m)
        {
            deviceMetricsSnapshot.samples.clear();
            deviceMetricsSnapshot.timestamp_ms = m.timestamp_ms;

            add_metric(deviceMetricsSnapshot, "cpu.usage", m.cpuUsage, m.timestamp_ms, anomaly_detection::metricType::Gauge);
            add_metric(deviceMetricsSnapshot, "cpu.temp", m.cpuTemp, m.timestamp_ms, anomaly_detection::metricType::Gauge);
            add_metric(deviceMetricsSnapshot, "cpu.core_count", m.coreCount, m.timestamp_ms, anomaly_detection::metricType::Gauge);

            if (m.coreCount > 0)
            {
                double normalizedLoad1m = static_cast<double>(m.loadAvg1m) / static_cast<double>(m.coreCount);
                double normalizedLoad5m = static_cast<double>(m.loadAvg5m) / static_cast<double>(m.coreCount);
                double normalizedLoad15m = static_cast<double>(m.loadAvg15m) / static_cast<double>(m.coreCount);

                add_metric(deviceMetricsSnapshot, "cpu.load_1m", normalizedLoad1m, m.timestamp_ms, anomaly_detection::metricType::Gauge);
                add_metric(deviceMetricsSnapshot, "cpu.load_5m", normalizedLoad5m, m.timestamp_ms, anomaly_detection::metricType::Gauge);
                add_metric(deviceMetricsSnapshot, "cpu.load_15m", normalizedLoad15m, m.timestamp_ms, anomaly_detection::metricType::Gauge);
            }

            for (std::size_t i = 0; i < m.perCoreUsage.size(); ++i)
            {
                std::string metricName = "cpu.core" + std::to_string(i) + ".usage";

                add_metric(deviceMetricsSnapshot,
                           metricName,
                           m.perCoreUsage[i],
                           m.timestamp_ms,
                           anomaly_detection::metricType::Gauge);
            }

            for (std::size_t i = 0; i < m.perCoreFreqMhz.size(); ++i)
            {
                std::string metricName = "cpu.core" + std::to_string(i) + ".freq_mhz";

                add_metric(deviceMetricsSnapshot,
                           metricName,
                           m.perCoreFreqMhz[i],
                           m.timestamp_ms,
                           anomaly_detection::metricType::Gauge);
            }

            add_metric(deviceMetricsSnapshot, "cpu.throttle_flags", m.throttleFlags, m.timestamp_ms, anomaly_detection::metricType::Flag);

            add_metric(deviceMetricsSnapshot, "memory.ram_used_mb", m.ramUsedMb, m.timestamp_ms, anomaly_detection::metricType::Gauge);
            add_metric(deviceMetricsSnapshot, "memory.ram_total_mb", m.ramTotalMb, m.timestamp_ms, anomaly_detection::metricType::Gauge);

            if (m.ramTotalMb > 0.0f)
            {
                double ramUsedPercent = static_cast<double>(m.ramUsedMb / m.ramTotalMb) * 100.0;

                add_metric(deviceMetricsSnapshot,
                           "memory.ram_used_pct",
                           ramUsedPercent,
                           m.timestamp_ms,
                           anomaly_detection::metricType::Gauge);
            }

            add_metric(deviceMetricsSnapshot, "memory.swap_used_mb", m.swapUsedMb, m.timestamp_ms, anomaly_detection::metricType::Gauge);

            add_metric(deviceMetricsSnapshot, "storage.disk_used_pct", m.diskUsedPct, m.timestamp_ms, anomaly_detection::metricType::Gauge);
            add_metric(deviceMetricsSnapshot, "storage.emmc_used_mb", m.emmcUsedMb, m.timestamp_ms, anomaly_detection::metricType::Gauge);
            add_metric(deviceMetricsSnapshot, "storage.emmc_total_mb", m.emmcTotalMb, m.timestamp_ms, anomaly_detection::metricType::Gauge);
            if (m.emmcTotalMb > 0.0f)
            {
                double emmcUsedPercent = static_cast<double>(m.emmcUsedMb / m.emmcTotalMb) * 100.0;

                add_metric(deviceMetricsSnapshot,
                           "storage.emmc_used_pct",
                           emmcUsedPercent,
                           m.timestamp_ms,
                           anomaly_detection::metricType::Gauge);
            }
            add_metric(deviceMetricsSnapshot, "storage.emmc_life_used_pct", m.emmcLifeUsed, m.timestamp_ms, anomaly_detection::metricType::Gauge);

            add_metric(deviceMetricsSnapshot,
                       "system.uptime_sec",
                       static_cast<double>(m.uptimeSec),
                       m.timestamp_ms,
                       anomaly_detection::metricType::Gauge);
        }

        void init_anomaly_detectors()
        {
            anomalyDetectors.clear();

            make_threshold_rule_creator();
            make_range_rule_creator();
            make_delta_rule_creator();
            make_slope_rule_creator();
            make_z_score_rule_creator();
            make_timeout_rule_creator();
            make_multi_condition_rule_creator();

            anomalyDetectors.push_back(std::make_unique<anomaly_detection::thresholdDetector>(thresholdRules));
            anomalyDetectors.push_back(std::make_unique<anomaly_detection::rangeCheckDetector>(rangeRules));
            anomalyDetectors.push_back(std::make_unique<anomaly_detection::deltaDetection>(deltaRules));
            anomalyDetectors.push_back(std::make_unique<anomaly_detection::slopeDetection>(slopeRules));
            anomalyDetectors.push_back(std::make_unique<anomaly_detection::zScoreDetection>(zScoreRules));
            anomalyDetectors.push_back(std::make_unique<anomaly_detection::timeoutDetector>(timeoutRules));
            anomalyDetectors.push_back(std::make_unique<anomaly_detection::multiConditionDetector>(multiConditionRules));

            SPDLOG_INFO("Initialized {} device anomaly detectors", anomalyDetectors.size());
        }

        void run_anomaly_detectors()
        {
            std::vector<anomaly_detection::anomalyEvent> allAnomalyEvents;

            for (const std::unique_ptr<anomaly_detection::baseDetector> &anomalyDetector : anomalyDetectors)
            {
                std::vector<anomaly_detection::anomalyEvent> anomalyEvents = anomalyDetector->update(deviceMetricsSnapshot);

                for (const anomaly_detection::anomalyEvent &event : anomalyEvents)
                {
                    SPDLOG_WARN(
                        "Device anomaly event detector={} severity={} metric={} value={} timestamp_ms={} message={}",
                        event.detectorName,
                        severity_text(event.severity_),
                        event.metricName,
                        event.value,
                        event.timestamp_ms,
                        event.message);

                    allAnomalyEvents.push_back(event);
                }
            }

            if (!allAnomalyEvents.empty())
            {
                core::interprocess::messageProtocol_.send_device_anomaly_data(allAnomalyEvents);
            }
        }

        // One CPU's accumulated jiffies, split into busy vs idle.
        struct CpuTime
        {
            std::uint64_t total = 0;
            std::uint64_t idle = 0;
        };

        // index 0 = aggregate ("cpu"), 1..N = per core ("cpu0".."cpuN-1")
        std::vector<CpuTime> read_cpu_times()
        {
            std::vector<CpuTime> out;
            std::ifstream f("/proc/stat");
            std::string line;
            while (std::getline(f, line))
            {
                if (line.rfind("cpu", 0) != 0)
                    break; // cpu lines are first; stop once they end

                std::istringstream ss(line);
                std::string label; // "cpu" or "cpuN"
                ss >> label;

                // user nice system idle iowait irq softirq steal guest guest_nice
                std::uint64_t v = 0, sum = 0, idle = 0;
                int col = 0;
                while (ss >> v)
                {
                    sum += v;
                    if (col == 3 || col == 4) // idle + iowait
                        idle += v;
                    ++col;
                }
                out.push_back({sum, idle});
            }
            return out;
        }

        float cpu_usage_pct(const CpuTime &prev, const CpuTime &cur)
        {
            const std::uint64_t dt = cur.total - prev.total;
            const std::uint64_t di = cur.idle - prev.idle;
            if (dt == 0)
                return 0.0f;
            return 100.0f * static_cast<float>(dt - di) / static_cast<float>(dt);
        }

        // read a whole small sysfs/proc file into a string
        std::string read_file(const char *path)
        {
            std::ifstream f(path);
            std::stringstream ss;
            ss << f.rdbuf();
            return ss.str();
        }

        float read_temp_c()
        {
            const std::string s = read_file("/sys/class/thermal/thermal_zone0/temp");
            if (s.empty())
                return 0.0f;
            return static_cast<float>(std::strtol(s.c_str(), nullptr, 10)) / 1000.0f;
        }

        std::uint32_t read_freq_mhz(unsigned cpu)
        {
            const std::string path =
                "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/cpufreq/scaling_cur_freq";
            const std::string s = read_file(path.c_str());
            if (s.empty())
                return 0;
            return static_cast<std::uint32_t>(std::strtoul(s.c_str(), nullptr, 10) / 1000); // kHz -> MHz
        }

        std::uint64_t read_uptime_sec()
        {
            const std::string s = read_file("/proc/uptime");
            if (s.empty())
                return 0;
            return static_cast<std::uint64_t>(std::strtod(s.c_str(), nullptr));
        }

        // /proc/meminfo values are in kB; we fill MB.
        void read_mem(deviceMetrics &m)
        {
            std::ifstream f("/proc/meminfo");
            std::string key;
            std::uint64_t val = 0;
            std::string unit;
            std::uint64_t memTotal = 0, memAvail = 0, swapTotal = 0, swapFree = 0;
            while (f >> key >> val >> unit)
            {
                if (key == "MemTotal:")
                    memTotal = val;
                else if (key == "MemAvailable:")
                    memAvail = val;
                else if (key == "SwapTotal:")
                    swapTotal = val;
                else if (key == "SwapFree:")
                    swapFree = val;
            }
            m.ramTotalMb = static_cast<float>(memTotal) / 1024.0f;
            m.ramUsedMb = static_cast<float>(memTotal - memAvail) / 1024.0f;
            m.swapUsedMb = static_cast<float>(swapTotal - swapFree) / 1024.0f;
        }

        // Storage is reported at two scopes:
        //  - diskUsedPct: fullness of the ROOT partition (the operational alarm:
        //    root filling up breaks logging/redis, regardless of chip size).
        //  - emmcTotalMb/emmcUsedMb: the whole physical eMMC/SD device, so you
        //    can see total chip capacity (e.g. 29.7 GB) vs how much is consumed
        //    across all of its partitions.
        void read_storage(deviceMetrics &m)
        {
            // root partition fullness (percent)
            struct statvfs root{};
            if (statvfs("/", &root) == 0)
            {
                const std::uint64_t total = static_cast<std::uint64_t>(root.f_blocks) * root.f_frsize;
                const std::uint64_t freeB = static_cast<std::uint64_t>(root.f_bfree) * root.f_frsize;
                m.diskUsedPct = total ? 100.0f * static_cast<float>(total - freeB) / static_cast<float>(total) : 0.0f;
            }

            // whole physical device size from sysfs (value is in 512-byte sectors)
            const std::string sz = read_file("/sys/block/mmcblk0/size");
            const std::uint64_t devBytes = sz.empty() ? 0 : std::strtoull(sz.c_str(), nullptr, 10) * 512ULL;
            m.emmcTotalMb = static_cast<float>(devBytes) / (1024.0f * 1024.0f);

            // sum used space across every mounted partition on mmcblk0
            std::uint64_t usedBytes = 0;
            std::ifstream mounts("/proc/mounts");
            std::string dev, mnt, rest;
            while (mounts >> dev >> mnt)
            {
                std::getline(mounts, rest); // discard the rest of the line
                if (dev.rfind("/dev/mmcblk0", 0) != 0)
                    continue;
                struct statvfs v{};
                if (statvfs(mnt.c_str(), &v) == 0)
                    usedBytes += (static_cast<std::uint64_t>(v.f_blocks) - v.f_bfree) * v.f_frsize;
            }
            m.emmcUsedMb = static_cast<float>(usedBytes) / (1024.0f * 1024.0f);
        }

        // vcgencmd get_throttled -> "throttled=0x...". Low 4 bits are the live
        // flags. Best effort: returns 0 if vcgencmd is missing or unreadable
        // (e.g. the process is not in the 'video' group / lacks /dev/vcio).
        std::uint8_t read_throttle_flags()
        {
            FILE *p = popen("vcgencmd get_throttled 2>/dev/null", "r");
            if (!p)
                return 0;
            char buf[128] = {0};
            std::uint8_t flags = 0;
            if (fgets(buf, sizeof(buf), p))
            {
                const char *eq = std::strchr(buf, '=');
                if (eq)
                    flags = static_cast<std::uint8_t>(std::strtoul(eq + 1, nullptr, 0) & 0xF);
            }
            pclose(p);
            return flags;
        }

        // /sys/block/mmcblk0/device/life_time -> "0x02 0x01" (typ A / typ B).
        // Each step = 10% of rated write life used. We report the worse of the
        // two as 0-100%. Returns 0 when the node is absent (SD cards, etc.).
        std::uint8_t read_emmc_life()
        {
            const std::string s = read_file("/sys/block/mmcblk0/device/life_time");
            if (s.empty())
                return 0;
            std::istringstream ss(s);
            unsigned a = 0, b = 0;
            ss >> std::hex >> a >> b;
            const unsigned worse = (a > b) ? a : b;
            return static_cast<std::uint8_t>(worse * 10); // step -> percent
        }
    } // namespace

    void main()
    {
        SPDLOG_INFO("deviceprocess thread running");

        // prime the CPU counters so the first computed usage is a real delta.
        std::vector<CpuTime> prev = read_cpu_times();
        std::uint8_t cachedEmmcLife = read_emmc_life();
        int cycle = 0;

        init_anomaly_detectors();

        while (1)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(kSampleIntervalMs));

            std::vector<CpuTime> cur = read_cpu_times();

            deviceMetrics m{};
            m.timestamp_ms = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());

            // --- cpu usage: aggregate (index 0) + per core (1..N) ---
            if (!cur.empty() && cur.size() == prev.size())
            {
                m.cpuUsage = cpu_usage_pct(prev[0], cur[0]);
                m.coreCount = static_cast<std::uint8_t>(cur.size() - 1);
                m.perCoreUsage.reserve(m.coreCount);
                for (std::size_t i = 1; i < cur.size(); ++i)
                    m.perCoreUsage.push_back(cpu_usage_pct(prev[i], cur[i]));
            }
            prev = std::move(cur);

            m.cpuTemp = read_temp_c();

            // current clock for each core (same path pattern per cpuN)
            m.perCoreFreqMhz.reserve(m.coreCount);
            for (unsigned i = 0; i < m.coreCount; ++i)
                m.perCoreFreqMhz.push_back(read_freq_mhz(i));

            double load[3] = {0, 0, 0};
            if (getloadavg(load, 3) == 3)
            {
                m.loadAvg1m = static_cast<float>(load[0]);
                m.loadAvg5m = static_cast<float>(load[1]);
                m.loadAvg15m = static_cast<float>(load[2]);
            }

            m.throttleFlags = read_throttle_flags();

            read_mem(m);
            read_storage(m);

            // eMMC life barely moves (months); refresh it occasionally only.
            if (++cycle >= kEmmcLifeEveryN)
            {
                cachedEmmcLife = read_emmc_life();
                cycle = 0;
            }
            m.emmcLifeUsed = cachedEmmcLife;

            m.uptimeSec = read_uptime_sec();

            // build "c0=12.3 c1=5.0 ..." for the per-core usage column
            std::string perCore;
            for (std::size_t i = 0; i < m.perCoreUsage.size(); ++i)
                perCore += fmt::format("c{}={:.1f} ", i, m.perCoreUsage[i]);

            // build "c0=1500 c1=600 ..." MHz for the per-core freq column
            std::string perFreq;
            for (std::size_t i = 0; i < m.perCoreFreqMhz.size(); ++i)
                perFreq += fmt::format("c{}={} ", i, m.perCoreFreqMhz[i]);

            SPDLOG_INFO(
                "deviceMetrics ts={} cpu={:.1f}% cores={} [{}] temp={:.1f}C "
                "freqMHz=[{}] load={:.2f}/{:.2f}/{:.2f} throttle=0x{:X} "
                "ram={:.0f}/{:.0f}MB swap={:.0f}MB disk={:.1f}% "
                "emmc={:.0f}/{:.0f}MB life={}% up={}s",
                m.timestamp_ms, m.cpuUsage, static_cast<unsigned>(m.coreCount), perCore,
                m.cpuTemp, perFreq, m.loadAvg1m, m.loadAvg5m, m.loadAvg15m,
                static_cast<unsigned>(m.throttleFlags), m.ramUsedMb, m.ramTotalMb, m.swapUsedMb,
                m.diskUsedPct, m.emmcUsedMb, m.emmcTotalMb, static_cast<unsigned>(m.emmcLifeUsed),
                m.uptimeSec);

            core::interprocess::messageProtocol_.send_device_data(m);


            make_device_metric_snapshot(m);
            run_anomaly_detectors();
        }
    }

} // namespace core::deviceprocess
