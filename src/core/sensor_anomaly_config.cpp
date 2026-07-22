#include "gateway/core/sensor_anomaly_config.hpp"
#include <stdexcept>

namespace core::sensorprocess
{
    namespace
    {
        std::string require_name(const nlohmann::json& item, const char* key)
        {
            const std::string name = item.value(key, std::string{});
            if (name.empty()) throw std::runtime_error(std::string(key) + " cannot be empty");
            return name;
        }

        anomaly_detection::severity parse_severity(const std::string& value, anomaly_detection::severity fallback)
        {
            if (value.empty()) return fallback;
            if (value == "info") return anomaly_detection::severity::Info;
            if (value == "warning") return anomaly_detection::severity::Warning;
            if (value == "critical") return anomaly_detection::severity::Critical;
            throw std::runtime_error("Unsupported anomaly severity: " + value);
        }

        anomaly_detection::compareOp parse_compare_op(const std::string& value)
        {
            if (value == "gt") return anomaly_detection::compareOp::GreaterThan;
            if (value == "gte") return anomaly_detection::compareOp::GreaterEqual;
            if (value == "lt") return anomaly_detection::compareOp::LessThan;
            if (value == "lte") return anomaly_detection::compareOp::LessEqual;
            if (value == "eq") return anomaly_detection::compareOp::Equal;
            if (value == "neq") return anomaly_detection::compareOp::NotEqual;
            throw std::runtime_error("Unsupported multi-condition op: " + value);
        }

        anomaly_detection::logicOp parse_logic_op(const std::string& value)
        {
            if (value == "all") return anomaly_detection::logicOp::All;
            if (value == "any") return anomaly_detection::logicOp::Any;
            throw std::runtime_error("Unsupported multi-condition logic: " + value);
        }

        std::vector<anomaly_detection::thresholdRule> parse_threshold_rules(const nlohmann::json& value)
        {
            std::vector<anomaly_detection::thresholdRule> rules;
            for (const nlohmann::json& item : value)
            {
                if (!item.is_object()) throw std::runtime_error("threshold rule must be an object");
                rules.push_back({
                    .metricName = require_name(item, "metric_name"),
                    .warningLimit = item.value("warning_limit", 0.0),
                    .criticalLimit = item.value("critical_limit", 0.0),
                    .triggerAbove = item.value("trigger_above", true),
                    .message = item.value("message", std::string{}),
                });
            }
            return rules;
        }

        std::vector<anomaly_detection::rangeRule> parse_range_rules(const nlohmann::json& value)
        {
            std::vector<anomaly_detection::rangeRule> rules;
            for (const nlohmann::json& item : value)
            {
                if (!item.is_object()) throw std::runtime_error("range rule must be an object");
                rules.push_back({
                    .metricName = require_name(item, "metric_name"),
                    .minValue = item.value("min_value", 0.0),
                    .maxValue = item.value("max_value", 0.0),
                    .severity_ = parse_severity(item.value("severity", std::string{}), anomaly_detection::severity::Warning),
                    .message = item.value("message", std::string{}),
                });
            }
            return rules;
        }

        std::vector<anomaly_detection::deltaRule> parse_delta_rules(const nlohmann::json& value)
        {
            std::vector<anomaly_detection::deltaRule> rules;
            for (const nlohmann::json& item : value)
            {
                if (!item.is_object()) throw std::runtime_error("delta rule must be an object");
                rules.push_back({
                    .metricName = require_name(item, "metric_name"),
                    .warningDelta = item.value("warning_delta", 0.0),
                    .criticalDelta = item.value("critical_delta", 0.0),
                    .triggerPositive = item.value("trigger_positive", true),
                    .maxSampleGapMs = item.value("max_sample_gap_ms", static_cast<std::uint64_t>(30000)),
                    .message = item.value("message", std::string{}),
                });
            }
            return rules;
        }

        std::vector<anomaly_detection::slopeRule> parse_slope_rules(const nlohmann::json& value)
        {
            std::vector<anomaly_detection::slopeRule> rules;
            for (const nlohmann::json& item : value)
            {
                if (!item.is_object()) throw std::runtime_error("slope rule must be an object");
                rules.push_back({
                    .metricName = require_name(item, "metric_name"),
                    .warningSlopePerMin = item.value("warning_slope_per_min", 0.0),
                    .criticalSlopePerMin = item.value("critical_slope_per_min", 0.0),
                    .minElapsedMs = item.value("min_elapsed_ms", static_cast<std::uint64_t>(10000)),
                    .minSamples = item.value("min_samples", static_cast<std::size_t>(5)),
                    .triggerPositive = item.value("trigger_positive", true),
                    .windowMs = item.value("window_ms", static_cast<std::uint64_t>(300000)),
                    .maxSampleGapMs = item.value("max_sample_gap_ms", static_cast<std::uint64_t>(30000)),
                    .message = item.value("message", std::string{}),
                });
            }
            return rules;
        }

        std::vector<anomaly_detection::zScoreRule> parse_z_score_rules(const nlohmann::json& value)
        {
            std::vector<anomaly_detection::zScoreRule> rules;
            for (const nlohmann::json& item : value)
            {
                if (!item.is_object()) throw std::runtime_error("z_score rule must be an object");
                rules.push_back({
                    .metricName = require_name(item, "metric_name"),
                    .warningZ = item.value("warning_z", 3.0),
                    .criticalZ = item.value("critical_z", 5.0),
                    .warmupSamples = item.value("warmup_samples", static_cast<std::size_t>(30)),
                    .minStdDev = item.value("min_std_dev", 0.0),
                    .minAbsDelta = item.value("min_abs_delta", 0.0),
                    .message = item.value("message", std::string{}),
                });
            }
            return rules;
        }

        std::vector<anomaly_detection::timeoutRule> parse_timeout_rules(const nlohmann::json& value)
        {
            std::vector<anomaly_detection::timeoutRule> rules;
            for (const nlohmann::json& item : value)
            {
                if (!item.is_object()) throw std::runtime_error("timeout rule must be an object");
                rules.push_back({
                    .metricName = require_name(item, "metric_name"),
                    .timeoutMs = item.value("timeout_ms", static_cast<std::uint64_t>(60000)),
                    .severity_ = parse_severity(item.value("severity", std::string{}), anomaly_detection::severity::Warning),
                    .message = item.value("message", std::string{}),
                });
            }
            return rules;
        }

        std::vector<anomaly_detection::condition> parse_conditions(const nlohmann::json& value)
        {
            if (!value.is_array()) throw std::runtime_error("multi_condition conditions must be an array");
            std::vector<anomaly_detection::condition> conditions;
            for (const nlohmann::json& item : value)
            {
                if (!item.is_object()) throw std::runtime_error("condition must be an object");
                conditions.push_back({
                    .metricName = require_name(item, "metric_name"),
                    .op = parse_compare_op(item.value("op", std::string{})),
                    .value = item.value("value", 0.0),
                });
            }
            if (conditions.empty()) throw std::runtime_error("multi_condition rule needs at least one condition");
            return conditions;
        }

        std::vector<anomaly_detection::multiConditionRule> parse_multi_condition_rules(const nlohmann::json& value)
        {
            std::vector<anomaly_detection::multiConditionRule> rules;
            for (const nlohmann::json& item : value)
            {
                if (!item.is_object()) throw std::runtime_error("multi_condition rule must be an object");
                rules.push_back({
                    .alarmName = require_name(item, "alarm_name"),
                    .conditions = parse_conditions(item.value("conditions", nlohmann::json::array())),
                    .logic = parse_logic_op(item.value("logic", std::string{"all"})),
                    .severity_ = parse_severity(item.value("severity", std::string{}), anomaly_detection::severity::Warning),
                    .message = item.value("message", std::string{}),
                });
            }
            return rules;
        }
    }

    sensorAnomalyConfig parse_sensor_anomaly_config(const nlohmann::json& payload)
    {
        if (!payload.is_object()) throw std::runtime_error("sensorAnomalyConfig payload must be an object");

        sensorAnomalyConfig config;
        config.sourceType = require_name(payload, "source_type");
        config.sourceId = require_name(payload, "source_id");
        config.thresholdRules = parse_threshold_rules(payload.value("threshold", nlohmann::json::array()));
        config.rangeRules = parse_range_rules(payload.value("range", nlohmann::json::array()));
        config.deltaRules = parse_delta_rules(payload.value("delta", nlohmann::json::array()));
        config.slopeRules = parse_slope_rules(payload.value("slope", nlohmann::json::array()));
        config.zScoreRules = parse_z_score_rules(payload.value("z_score", nlohmann::json::array()));
        config.timeoutRules = parse_timeout_rules(payload.value("timeout", nlohmann::json::array()));
        config.multiConditionRules = parse_multi_condition_rules(payload.value("multi_condition", nlohmann::json::array()));
        return config;
    }
}
