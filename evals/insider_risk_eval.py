"""Insider-risk evaluation on hand-labeled fixture scenarios."""

from __future__ import annotations

import json
from pathlib import Path

from analytics.insider_risk import evaluate_scored_events, score_insider_event
from analytics.utils import utcnow

DEFAULT_DATASET_PATH = Path("fixtures/insider_scenarios.json")


def run_insider_risk_evaluation(dataset_path=DEFAULT_DATASET_PATH, threshold=55.0):
    fixtures = json.loads(Path(dataset_path).read_text(encoding="utf-8"))
    scored_events = [score_insider_event(row) for row in fixtures if isinstance(row, dict)]
    report = evaluate_scored_events(scored_events, threshold=threshold)
    report.update(
        {
            "generated_at": utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "dataset_path": str(dataset_path),
            "cases_total": len(scored_events),
            "positives_expected": report["counts"]["support"],
        }
    )
    return report


def render_insider_risk_eval_markdown(report):
    counts = report["counts"]
    metrics = report["metrics"]
    lines = [
        "# Insider Risk Evaluation",
        "",
        f"Generated: {report['generated_at']} UTC",
        f"Dataset: `{report['dataset_path']}`",
        f"Threshold: **{report['threshold']:.1f}**",
        f"Cases: **{report['cases_total']}** (expected positives: **{report['positives_expected']}**)",
        "",
        "## Aggregate Metrics",
        f"- Precision: **{metrics['precision']:.4f}**",
        f"- Recall: **{metrics['recall']:.4f}**",
        f"- F1: **{metrics['f1']:.4f}**",
        "",
        "## Confusion Totals",
        "| TP | FP | FN | TN |",
        "|---:|---:|---:|---:|",
        f"| {counts['tp']} | {counts['fp']} | {counts['fn']} | {counts['tn']} |",
        "",
        "## Per-Scenario",
        "| Scenario | Subject | Score | Expected Positive | Predicted Positive | Tier | Top Reason Codes |",
        "|---|---|---:|---:|---:|---|---|",
    ]

    for row in report["cases"]:
        reasons = ", ".join((row.get("reason_codes") or [])[:3]) or "none"
        lines.append(
            "| {scenario} | {subject} | {score:.1f} | {expected} | {predicted} | {tier} | {reasons} |".format(
                scenario=row.get("scenario_id") or "",
                subject=row.get("subject_id") or "",
                score=float(row.get("score") or 0.0),
                expected="yes" if row.get("expected_positive") else "no",
                predicted="yes" if row.get("predicted_positive") else "no",
                tier=row.get("risk_tier") or "",
                reasons=reasons,
            )
        )
    lines.append("")
    return "\n".join(lines)
