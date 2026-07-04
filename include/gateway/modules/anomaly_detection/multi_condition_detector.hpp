#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <string_view>
#include "gateway/modules/anomaly_detection/metric.hpp"
#include "gateway/modules/anomaly_detection/event.hpp"
#include "gateway/modules/anomaly_detection/detector.hpp"

namespace anomaly_detection
{

    enum class compareOp
    {
        GreaterThan,
        GreaterEqual,
        LessThan,
        LessEqual,
        Equal,
        NotEqual
    };

    enum class logicOp
    {
        All,
        Any
    };

    struct condition
    {
        std::string metricName;
        compareOp op;
        double value;
    };

    struct multiConditionRule
    {
        std::string alarmName;
        std::vector<condition> conditions;
        logicOp logic;
        severity severity_;
        std::string message;
    };

    class multiConditionDetector : public baseDetector
    {
    public:
        explicit multiConditionDetector(std::vector<multiConditionRule> rules);

        std::string_view name() const override;

        std::vector<anomalyEvent> update(const metricSnapshot &snapshot) override;

    private:
        bool evaluate_condition(double metricValue,
                                compareOp op,
                                double ruleValue) const;

        anomalyEvent make_event(const metricSnapshot &snapshot,
                                severity severity_,
                                std::string_view alarmName,
                                std::string_view message);

        std::vector<multiConditionRule> rules_;
    };

}