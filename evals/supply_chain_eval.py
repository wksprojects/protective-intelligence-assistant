"""Supply-chain risk scaffold evaluation on fixture vendor profiles."""

from __future__ import annotations

import json
from pathlib import Path

from analytics.supply_chain_risk import score_vendor_profile
from analytics.utils import utcnow

DEFAULT_DATASET_PATH = Path("fixtures/supply_chain_scenarios.json")
POSITIVE_LABELS = {"flagged", "watch", "high_risk"}


def _evaluate_scored_profiles(scored_profiles: list[dict], threshold: float = 45.0):
    safe_threshold = max(0.0, min(float(threshold), 100.0))
    tp = fp = fn = tn = 0
    rows = []

    for profile in scored_profiles:
        expected_label = str(profile.get("expected_label") or "").strip().lower()
        expected_positive = expected_label in POSITIVE_LABELS
        predicted_positive = float(profile.get("vendor_risk_score") or 0.0) >= safe_threshold

        if predicted_positive and expected_positive:
            tp += 1
        elif predicted_positive and not expected_positive:
            fp += 1
        elif not predicted_positive and expected_positive:
            fn += 1
        else:
            tn += 1

        rows.append(
            {
                "profile_id": profile.get("profile_id"),
                "vendor_name": profile.get("vendor_name"),
                "expected_label": expected_label or "unknown",
                "expected_positive": expected_positive,
                "predicted_positive": predicted_positive,
                "risk_tier": profile.get("risk_tier"),
                "score": round(float(profile.get("vendor_risk_score") or 0.0), 3),
                "reason_codes": profile.get("reason_codes") or [],
            }
        )

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "threshold": safe_threshold,
        "counts": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "support": tp + fn},
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "cases": rows,
    }


def run_supply_chain_evaluation(dataset_path=DEFAULT_DATASET_PATH, threshold=45.0):
    fixtures = json.loads(Path(dataset_path).read_text(encoding="utf-8"))
    scored_profiles = [score_vendor_profile(profile) for profile in fixtures if isinstance(profile, dict)]
    report = _evaluate_scored_profiles(scored_profiles, threshold=threshold)
    report.update(
        {
            "generated_at": utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "dataset_path": str(dataset_path),
            "cases_total": len(scored_profiles),
            "positives_expected": report["counts"]["support"],
        }
    )
    return report


def render_supply_chain_eval_markdown(report):
    counts = report["counts"]
    metrics = report["metrics"]
    lines = [
        "# Supply Chain Risk Evaluation",
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
        "## Per-Profile",
        "| Profile | Vendor | Score | Expected Label | Predicted Positive | Tier | Top Reason Codes |",
        "|---|---|---:|---|---:|---|---|",
    ]
    for row in report["cases"]:
        reasons = ", ".join((row.get("reason_codes") or [])[:3]) or "none"
        lines.append(
            "| {profile} | {vendor} | {score:.1f} | {label} | {predicted} | {tier} | {reasons} |".format(
                profile=row.get("profile_id") or "",
                vendor=row.get("vendor_name") or "",
                score=float(row.get("score") or 0.0),
                label=row.get("expected_label") or "unknown",
                predicted="yes" if row.get("predicted_positive") else "no",
                tier=row.get("risk_tier") or "",
                reasons=reasons,
            )
        )
    lines.append("")
    return "\n".join(lines)
