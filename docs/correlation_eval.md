# Correlation Engine Evaluation

Generated: 2026-10-01 00:49:56 UTC
Dataset: `fixtures/correlation_eval_cases.json`
Cases: **8** (exact-match cases: **6**)

Dataset note: includes deliberate near-miss/adversarial cases (cross-source term collision, actor-alias variation) to avoid inflated scores.

## Aggregate Pairwise Metrics
- Precision: **0.8750**
- Recall: **0.8750**
- F1: **0.8750**
- Support (positive pairs): **8**
- Cases with false positives: **1** (ambiguous_cross_source_term_collision)
- Cases with false negatives: **1** (actor_alias_normalization_miss)

## Pair Confusion Totals
| TP | FP | FN | TN | Total Pairs |
|---:|---:|---:|---:|---:|
| 7 | 1 | 1 | 5 | 14 |

## Per-Case Metrics
| Case | Alerts | Expected Pairs | Predicted Pairs | TP | FP | FN | Precision | Recall | F1 | Exact Match |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| actor_handle_cross_platform | 3 | 1 | 1 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1 |
| shared_poi_cross_source | 2 | 1 | 1 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1 |
| shared_domain_indicator | 3 | 1 | 1 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1 |
| shared_url_indicator | 2 | 1 | 1 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1 |
| distinct_noise_unlinked | 2 | 0 | 0 | 0 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 1 |
| ambiguous_cross_source_term_collision | 2 | 0 | 1 | 0 | 1 | 0 | 0.0000 | 0.0000 | 0.0000 | 0 |
| actor_alias_normalization_miss | 2 | 1 | 0 | 0 | 0 | 1 | 0.0000 | 0.0000 | 0.0000 | 0 |
| three_alert_actor_chain | 3 | 3 | 3 | 3 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1 |
