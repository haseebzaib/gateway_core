#include "gateway/modules/anomaly_detection/multi_condition_detector.hpp"
#include "spdlog/spdlog.h"

namespace anomaly_detection
{

    multiConditionDetector::multiConditionDetector(std::vector<multiConditionRule> rules)
        : rules_(std::move(rules))
    {
    }

    std::string_view multiConditionDetector::name() const
    {
        return "multiConditionDetector";
    }

    std::vector<anomalyEvent> multiConditionDetector::update(const metricSnapshot &snapshot)
    {
        std::vector<anomalyEvent> events;

        std::unordered_map<std::string, const metricSample *> sampleMap;

        for (const metricSample &sample : snapshot.samples)
        {
            sampleMap.emplace(sample.name, &sample);
        }

        for (const multiConditionRule &rule : rules_)
        {
            if (rule.conditions.empty())
            {
                continue;
            }

            bool ruleMatched = false;

            if (rule.logic == logicOp::All)
            {
                ruleMatched = true;
                for (const condition &cond : rule.conditions)
                {
                    std::unordered_map<std::string, const metricSample *>::iterator it =
                        sampleMap.find(cond.metricName);
                    if (it == sampleMap.end())
                    {
                        ruleMatched = false;
                        break;
                    }

                    const metricSample *sample = it->second;

                    bool conditionMatched = evaluate_condition(sample->value,
                                                               cond.op,
                                                               cond.value);

                    if (!conditionMatched)
                    {
                        ruleMatched = false;
                        break;
                    }
                }
            }
            else if (rule.logic == logicOp::Any)
            {
                ruleMatched = false;

                for (const condition &cond : rule.conditions)
                {
                    std::unordered_map<std::string, const metricSample *>::const_iterator it =
                        sampleMap.find(cond.metricName);

                    if (it == sampleMap.end())
                    {
                        continue;
                    }

                    const metricSample *sample = it->second;

                    bool conditionMatched = evaluate_condition(sample->value,
                                                               cond.op,
                                                               cond.value);

                    if (conditionMatched)
                    {
                        ruleMatched = true;
                        break;
                    }
                }
            }

            if (ruleMatched)
            {
                events.push_back(make_event(snapshot,
                                            rule.severity_,
                                            rule.alarmName,
                                            rule.message));
            }

        }

        return events;
    }

    bool multiConditionDetector::evaluate_condition(double metricValue,
                                                    compareOp op,
                                                    double ruleValue) const
    {
        switch (op)
        {
        case compareOp::GreaterThan:
            return metricValue > ruleValue;

        case compareOp::GreaterEqual:
            return metricValue >= ruleValue;

        case compareOp::LessThan:
            return metricValue < ruleValue;

        case compareOp::LessEqual:
            return metricValue <= ruleValue;

        case compareOp::Equal:
            return metricValue == ruleValue;

        case compareOp::NotEqual:
            return metricValue != ruleValue;
        }

        return false;
    }


    anomalyEvent multiConditionDetector::make_event(const metricSnapshot& snapshot,
                                                    severity severity_,
                                                    std::string_view alarmName,
                                                    std::string_view message)
    {
        return anomalyEvent{
            .detectorName = std::string{name()},
            .metricName = std::string{alarmName},
            .severity_ = severity_,
            .value = 0.0,
            .message = std::string{message},
            .timestamp_ms = snapshot.timestamp_ms
        };
    }

}