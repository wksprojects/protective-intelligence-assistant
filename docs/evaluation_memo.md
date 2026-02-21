# Evaluation Memo: Quantitative Protective Intelligence

Generated: 2026-02-21 21:00:29 UTC

## Summary
- Benchmark size: **13** EP scenarios
- Multi-factor model severity accuracy: **76.9%**
- Naive baseline severity accuracy: **38.5%**
- Absolute accuracy lift: **38.5%**

## Escalation Quality (High/Critical as Positive)

| Model | Precision | Recall | F1 | False Positives |
|---|---:|---:|---:|---:|
| Naive baseline | 0.667 | 0.750 | 0.706 | 3 |
| Multi-factor | 1.000 | 0.750 | 0.857 | 0 |

## Outcome Deltas
- False-positive reduction: **3 alerts** (100.0%)
- Escalation-time saved on benchmark: **0.30 analyst-hours**
- Projected time saved per 1,000 triaged alerts (same FP-rate delta): **23.1 analyst-hours**

## Method
1. Use the internal backtest scenarios in `analytics/backtesting.py`.
2. Score each scenario with:
   - Naive baseline: `keyword_weight * 20`
   - Multi-factor model: `compute_risk_score(...)`
3. Compare predicted vs expected severity.
4. Compute binary escalation metrics where positive = `high|critical`.

## Notes
- This memo is deterministic and reproducible via `make evaluate`.
- Time-saved estimate assumes **6 minutes** analyst effort per escalated alert.
