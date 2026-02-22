# Evaluation Memo: Quantitative Protective Intelligence

Generated: 2026-02-21 23:26:58 UTC

## Summary
- Benchmark size: **35** EP scenarios (initial benchmark)
- Multi-factor model severity accuracy: **68.6%**
- ML classifier severity accuracy (LOO-CV): **68.6%**
- Naive baseline severity accuracy: **51.4%**

## Escalation Quality (High/Critical as Positive)

| Model | Precision | Recall | F1 | False Positives |
|---|---:|---:|---:|---:|
| Naive baseline | 0.619 | 0.812 | 0.703 | 8 |
| Multi-factor (rules) | 0.867 | 0.812 | 0.839 | 2 |
| ML classifier (LOO-CV) | 0.867 | 0.812 | 0.839 | 2 |

## ML Classifier Details
- **Pipeline**: TF-IDF(alert text, bigrams) + StandardScaler(numeric features) → Logistic Regression
- **Features**: alert description text, keyword_weight, source_credibility, frequency_factor, recency_hours
- **Evaluation**: Leave-one-out cross-validation (appropriate for n=35)
- **Method**: `analytics/ml_classifier.py`

## Outcome Deltas (Multi-Factor vs Baseline)
- False-positive reduction: **6 alerts** (75.0%)
- Escalation-time saved on benchmark: **0.60 analyst-hours**
- Projected time saved per 1,000 triaged alerts (same FP-rate delta): **17.1 analyst-hours**

## Method
1. Use the internal backtest scenarios in `analytics/backtesting.py` (n=35).
2. Score each scenario with:
   - Naive baseline: `keyword_weight * 20`
   - Multi-factor model: `compute_risk_score(...)` (keyword × frequency × credibility × recency)
   - ML classifier: LOO-CV predictions from `analytics/ml_classifier.py`
3. Compare predicted vs expected severity.
4. Compute binary escalation metrics where positive = `high|critical`.

## Notes
- This memo is deterministic and reproducible via `make evaluate`.
- Time-saved estimate assumes **6 minutes** analyst effort per escalated alert.
- Benchmark is synthetic. Expanding scenario coverage is on the roadmap.
