# Supply Chain Risk Evaluation

Generated: 2026-02-27 21:06:36 UTC
Dataset: `fixtures/supply_chain_scenarios.json`
Threshold: **45.0**
Cases: **6** (expected positives: **5**)

## Aggregate Metrics
- Precision: **1.0000**
- Recall: **0.8000**
- F1: **0.8889**

## Confusion Totals
| TP | FP | FN | TN |
|---:|---:|---:|---:|
| 4 | 0 | 1 | 1 |

## Per-Profile
| Profile | Vendor | Score | Expected Label | Predicted Positive | Tier | Top Reason Codes |
|---|---|---:|---|---:|---|---|
| sc-001 | Northbridge Identity Operations | 99.4 | flagged | yes | HIGH | geographic_exposure_high, single_point_of_failure, privilege_scope_broad |
| sc-002 | Harborview Facilities Services | 19.3 | clean | no | LOW | baseline_monitoring |
| sc-003 | Blue Meridian Travel Partners | 47.5 | watch | yes | GUARDED | sensitive_data_exposure |
| sc-004 | Aster Cloud Analytics | 83.3 | flagged | yes | HIGH | geographic_exposure_high, single_point_of_failure, privilege_scope_broad |
| sc-005 | Summit Badge Integrations | 70.8 | watch | yes | ELEVATED | single_point_of_failure, privilege_scope_broad, sensitive_data_exposure |
| sc-006 | Praxis Payroll Outsourcing | 40.5 | watch | no | GUARDED | sensitive_data_exposure |
