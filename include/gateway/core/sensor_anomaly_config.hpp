#pragma once

#include "gateway/modules/anomaly_detection/threshold_detector.hpp"
#include "gateway/modules/anomaly_detection/range_check_detector.hpp"
#include "gateway/modules/anomaly_detection/delta_detector.hpp"
#include "gateway/modules/anomaly_detection/slope_detector.hpp"
#include "gateway/modules/anomaly_detection/z_score_detector.hpp"
#include "gateway/modules/anomaly_detection/timeout_detector.hpp"
#include "gateway/modules/anomaly_detection/multi_condition_detector.hpp"
#include "gateway/utils/thirdparty/json.hpp"
#include <string>
#include <vector>

namespace core::sensorprocess
{
    // Anomaly detection rules for one sensor source (one Modbus TCP connection,
    // one RS485/Modbus RTU port, or one RS232 sensor port). Rule vectors reuse
    // the existing, unmodified detector Rule structs from
    // gateway/modules/anomaly_detection — this config layer only parses JSON
    // into them, it does not change detector behavior.
    struct sensorAnomalyConfig
    {
        std::string sourceType {};
        std::string sourceId {};
        std::vector<anomaly_detection::thresholdRule> thresholdRules {};
        std::vector<anomaly_detection::rangeRule> rangeRules {};
        std::vector<anomaly_detection::deltaRule> deltaRules {};
        std::vector<anomaly_detection::slopeRule> slopeRules {};
        std::vector<anomaly_detection::zScoreRule> zScoreRules {};
        std::vector<anomaly_detection::timeoutRule> timeoutRules {};
        std::vector<anomaly_detection::multiConditionRule> multiConditionRules {};
    };

    // payload shape:
    // {
    //   "source_type": "modbusTcp", "source_id": "conn_1",
    //   "threshold":       [{"metric_name","warning_limit","critical_limit","trigger_above","message"}],
    //   "range":           [{"metric_name","min_value","max_value","severity","message"}],
    //   "delta":           [{"metric_name","warning_delta","critical_delta","trigger_positive","max_sample_gap_ms","message"}],
    //   "slope":           [{"metric_name","warning_slope_per_min","critical_slope_per_min","min_elapsed_ms","min_samples","trigger_positive","window_ms","max_sample_gap_ms","message"}],
    //   "z_score":         [{"metric_name","warning_z","critical_z","warmup_samples","min_std_dev","min_abs_delta","message"}],
    //   "timeout":         [{"metric_name","timeout_ms","severity","message"}],
    //   "multi_condition": [{"alarm_name","conditions":[{"metric_name","op","value"}],"logic","severity","message"}]
    // }
    // multi_condition conditions must reference metrics on this same source
    // (source_type/source_id) — cross-source combined alarms are not supported.
    sensorAnomalyConfig parse_sensor_anomaly_config(const nlohmann::json& payload);
}
