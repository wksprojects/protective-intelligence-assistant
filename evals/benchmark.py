"""Benchmark metric helpers for README/docs reporting."""

from __future__ import annotations

from analytics.backtesting import run_backtest
from analytics.ml_classifier import evaluate_loo

_ACTIONABLE = {"high", "critical"}


def _binary_confusion(cases, pred_key: str):
    tp = fp = tn = fn = 0
    for case in cases:
        actual_positive = case["expected_severity"] in _ACTIONABLE
        predicted_positive = case[pred_key] in _ACTIONABLE
        if predicted_positive and actual_positive:
            tp += 1
        elif predicted_positive and not actual_positive:
            fp += 1
        elif not predicted_positive and actual_positive:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _precision(tp, fp):
    return tp / (tp + fp) if (tp + fp) else 0.0


def _recall(tp, fn):
    return tp / (tp + fn) if (tp + fn) else 0.0


def _f1(precision, recall):
    return (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0


def build_benchmark_metrics():
    backtest = run_backtest()
    ml = evaluate_loo()
    incidents = backtest["incidents"]
    aggregate = backtest["aggregate"]

    baseline_conf = _binary_confusion(incidents, "baseline_severity")
    rules_conf = _binary_confusion(incidents, "full_severity")

    rules_precision = _precision(rules_conf["tp"], rules_conf["fp"])
    rules_recall = _recall(rules_conf["tp"], rules_conf["fn"])
    rules_f1 = _f1(rules_precision, rules_recall)

    baseline_precision = _precision(baseline_conf["tp"], baseline_conf["fp"])
    baseline_recall = _recall(baseline_conf["tp"], baseline_conf["fn"])
    baseline_f1 = _f1(baseline_precision, baseline_recall)

    return {
        "n_cases": len(incidents),
        "severity_accuracy": {
            "baseline": aggregate["baseline_detection_rate"],
            "rules": aggregate["full_detection_rate"],
            "ml": ml["accuracy"],
        },
        "escalation_quality": {
            "baseline": {
                "precision": baseline_precision,
                "recall": baseline_recall,
                "f1": baseline_f1,
                "false_positives": baseline_conf["fp"],
            },
            "rules": {
                "precision": rules_precision,
                "recall": rules_recall,
                "f1": rules_f1,
                "false_positives": rules_conf["fp"],
            },
            "ml": {
                "precision": ml["precision"],
                "recall": ml["recall"],
                "f1": ml["f1"],
                "false_positives": ml["fp"],
            },
        },
    }


def render_benchmark_markdown(metrics):
    sev = metrics["severity_accuracy"]
    eq = metrics["escalation_quality"]
    return "\n".join(
        [
            "# Benchmark Table",
            "",
            f"Benchmark scenarios: **{metrics['n_cases']}**",
            "",
            "## Severity Accuracy",
            "| Model | Accuracy |",
            "|---|---:|",
            f"| Baseline | {sev['baseline']:.1%} |",
            f"| Multi-factor Rules | {sev['rules']:.1%} |",
            f"| ML (LOO-CV) | {sev['ml']:.1%} |",
            "",
            "## Escalation Quality (High/Critical = Positive)",
            "| Model | Precision | Recall | F1 | False Positives |",
            "|---|---:|---:|---:|---:|",
            (
                f"| Baseline | {eq['baseline']['precision']:.3f} | {eq['baseline']['recall']:.3f} | "
                f"{eq['baseline']['f1']:.3f} | {eq['baseline']['false_positives']} |"
            ),
            (
                f"| Multi-factor Rules | {eq['rules']['precision']:.3f} | {eq['rules']['recall']:.3f} | "
                f"{eq['rules']['f1']:.3f} | {eq['rules']['false_positives']} |"
            ),
            (
                f"| ML (LOO-CV) | {eq['ml']['precision']:.3f} | {eq['ml']['recall']:.3f} | "
                f"{eq['ml']['f1']:.3f} | {eq['ml']['false_positives']} |"
            ),
            "",
        ]
    )
