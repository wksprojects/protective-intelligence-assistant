# Insider Risk Evaluation

Generated: 2026-02-27 21:06:34 UTC
Dataset: `fixtures/insider_scenarios.json`
Threshold: **55.0**
Cases: **10** (expected positives: **5**)

## Aggregate Metrics
- Precision: **1.0000**
- Recall: **1.0000**
- F1: **1.0000**

## Confusion Totals
| TP | FP | FN | TN |
|---:|---:|---:|---:|
| 5 | 0 | 0 | 5 |

## Per-Scenario
| Scenario | Subject | Score | Expected Positive | Predicted Positive | Tier | Top Reason Codes |
|---|---|---:|---:|---:|---|---|
| ins-001 | EMP-1042 | 88.4 | yes | yes | CRITICAL | access_escalation_signal, access_pattern_deviation_high, badge_logical_mismatch |
| ins-002 | EMP-1042 | 62.8 | yes | yes | ELEVATED | access_pattern_deviation_high, cumulative_risk_acceleration, hr_context_stressor |
| ins-003 | EMP-2209 | 15.8 | no | no | LOW | taxonomy_temporal_anomalies |
| ins-004 | EMP-3377 | 19.0 | no | no | LOW | taxonomy_data_staging |
| ins-005 | EMP-8891 | 60.2 | yes | yes | ELEVATED | access_escalation_signal, access_pattern_deviation_high, cumulative_risk_acceleration |
| ins-006 | EMP-6613 | 16.3 | no | no | LOW | taxonomy_temporal_anomalies |
| ins-007 | EMP-5074 | 57.3 | yes | yes | ELEVATED | access_escalation_signal, access_pattern_deviation_high, cumulative_risk_acceleration |
| ins-008 | EMP-1188 | 8.9 | no | no | LOW | isolated_benign_anomaly |
| ins-009 | EMP-7415 | 68.5 | yes | yes | ELEVATED | access_pattern_deviation_high, communication_metadata_shift, cumulative_risk_acceleration |
| ins-010 | EMP-5520 | 13.6 | no | no | LOW | taxonomy_temporal_anomalies |
