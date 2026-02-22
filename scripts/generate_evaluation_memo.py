#!/usr/bin/env python3
"""
Generate a short quantitative evaluation memo from the built-in EP backtest.

Output:
    docs/evaluation_memo.md
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from analytics.backtesting import run_backtest
from analytics.ml_classifier import evaluate_loo

ACTIONABLE_SEVERITIES = {"high", "critical"}
TRIAGE_MINUTES_PER_ESCALATION = 6.0


def _to_binary_confusion(cases, pred_key: str):
    tp = fp = tn = fn = 0
    for case in cases:
        actual_positive = case["expected_severity"] in ACTIONABLE_SEVERITIES
        predicted_positive = case[pred_key] in ACTIONABLE_SEVERITIES
        if predicted_positive and actual_positive:
            tp += 1
        elif predicted_positive and not actual_positive:
            fp += 1
        elif (not predicted_positive) and actual_positive:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) else 0.0


def _recall(tp: int, fn: int) -> float:
    return tp / (tp + fn) if (tp + fn) else 0.0


def _f1(precision: float, recall: float) -> float:
    return (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0


def _render_markdown(payload: dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""# Evaluation Memo: Quantitative Protective Intelligence

Generated: {ts}

## Summary
- Benchmark size: **{payload["n_cases"]}** EP scenarios (initial benchmark)
- Multi-factor model severity accuracy: **{payload["full_accuracy"]:.1%}**
- ML classifier severity accuracy (LOO-CV): **{payload["ml_accuracy"]:.1%}**
- Naive baseline severity accuracy: **{payload["baseline_accuracy"]:.1%}**

## Escalation Quality (High/Critical as Positive)

| Model | Precision | Recall | F1 | False Positives |
|---|---:|---:|---:|---:|
| Naive baseline | {payload["baseline_precision"]:.3f} | {payload["baseline_recall"]:.3f} | {payload["baseline_f1"]:.3f} | {payload["baseline_fp"]} |
| Multi-factor (rules) | {payload["full_precision"]:.3f} | {payload["full_recall"]:.3f} | {payload["full_f1"]:.3f} | {payload["full_fp"]} |
| ML classifier (LOO-CV) | {payload["ml_precision"]:.3f} | {payload["ml_recall"]:.3f} | {payload["ml_f1"]:.3f} | {payload["ml_fp"]} |

## ML Classifier Details
- **Pipeline**: TF-IDF(alert text, bigrams) + StandardScaler(numeric features) → Logistic Regression
- **Features**: alert description text, keyword_weight, source_credibility, frequency_factor, recency_hours
- **Evaluation**: Leave-one-out cross-validation (appropriate for n={payload["n_cases"]})
- **Method**: `analytics/ml_classifier.py`

## Outcome Deltas (Multi-Factor vs Baseline)
- False-positive reduction: **{payload["fp_reduction_abs"]} alerts** ({payload["fp_reduction_pct"]:.1%})
- Escalation-time saved on benchmark: **{payload["time_saved_hours"]:.2f} analyst-hours**
- Projected time saved per 1,000 triaged alerts (same FP-rate delta): **{payload["projected_hours_saved_per_1000"]:.1f} analyst-hours**

## Method
1. Use the internal backtest scenarios in `analytics/backtesting.py` (n={payload["n_cases"]}).
2. Score each scenario with:
   - Naive baseline: `keyword_weight * 20`
   - Multi-factor model: `compute_risk_score(...)` (keyword × frequency × credibility × recency)
   - ML classifier: LOO-CV predictions from `analytics/ml_classifier.py`
3. Compare predicted vs expected severity.
4. Compute binary escalation metrics where positive = `high|critical`.

## Notes
- This memo is deterministic and reproducible via `make evaluate`.
- Time-saved estimate assumes **{int(TRIAGE_MINUTES_PER_ESCALATION)} minutes** analyst effort per escalated alert.
- Benchmark is synthetic. Expanding scenario coverage is on the roadmap.
"""


def main():
    results = run_backtest()
    cases = results["incidents"]
    n_cases = len(cases)
    if n_cases == 0:
        raise RuntimeError("Backtest returned zero cases.")

    baseline_conf = _to_binary_confusion(cases, "baseline_severity")
    full_conf = _to_binary_confusion(cases, "full_severity")

    baseline_precision = _precision(baseline_conf["tp"], baseline_conf["fp"])
    baseline_recall = _recall(baseline_conf["tp"], baseline_conf["fn"])
    baseline_f1 = _f1(baseline_precision, baseline_recall)

    full_precision = _precision(full_conf["tp"], full_conf["fp"])
    full_recall = _recall(full_conf["tp"], full_conf["fn"])
    full_f1 = _f1(full_precision, full_recall)

    aggregate = results["aggregate"]
    baseline_accuracy = aggregate["baseline_detection_rate"]
    full_accuracy = aggregate["full_detection_rate"]

    fp_reduction_abs = max(0, baseline_conf["fp"] - full_conf["fp"])
    fp_reduction_pct = (
        fp_reduction_abs / baseline_conf["fp"] if baseline_conf["fp"] > 0 else 0.0
    )
    time_saved_hours = (fp_reduction_abs * TRIAGE_MINUTES_PER_ESCALATION) / 60.0

    baseline_fp_rate = baseline_conf["fp"] / n_cases
    full_fp_rate = full_conf["fp"] / n_cases
    projected_hours_saved_per_1000 = (
        (baseline_fp_rate - full_fp_rate) * 1000.0 * TRIAGE_MINUTES_PER_ESCALATION / 60.0
    )

    # ML classifier evaluation
    ml_results = evaluate_loo()

    payload = {
        "n_cases": n_cases,
        "baseline_accuracy": baseline_accuracy,
        "full_accuracy": full_accuracy,
        "accuracy_lift": full_accuracy - baseline_accuracy,
        "baseline_precision": baseline_precision,
        "baseline_recall": baseline_recall,
        "baseline_f1": baseline_f1,
        "full_precision": full_precision,
        "full_recall": full_recall,
        "full_f1": full_f1,
        "baseline_fp": baseline_conf["fp"],
        "full_fp": full_conf["fp"],
        "fp_reduction_abs": fp_reduction_abs,
        "fp_reduction_pct": fp_reduction_pct,
        "time_saved_hours": time_saved_hours,
        "projected_hours_saved_per_1000": projected_hours_saved_per_1000,
        "ml_accuracy": ml_results["accuracy"],
        "ml_precision": ml_results["precision"],
        "ml_recall": ml_results["recall"],
        "ml_f1": ml_results["f1"],
        "ml_fp": ml_results["fp"],
    }

    output = Path("docs/evaluation_memo.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_render_markdown(payload), encoding="utf-8")
    print(f"Evaluation memo written: {output}")
    print(f"  Scenarios: {n_cases}")
    print(f"  Baseline accuracy: {baseline_accuracy:.1%}")
    print(f"  Multi-factor accuracy: {full_accuracy:.1%}")
    print(f"  ML classifier accuracy (LOO-CV): {ml_results['accuracy']:.1%}")


if __name__ == "__main__":
    main()
