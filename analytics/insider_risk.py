"""Insider-risk scoring with explainable weighted factors."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from analytics.utils import parse_timestamp
from database.init_db import get_connection

SIGNAL_WEIGHTS = {
    "access_pattern_deviation": 0.24,
    "data_volume_anomaly": 0.22,
    "physical_logical_mismatch": 0.14,
    "access_escalation": 0.14,
    "communication_metadata_anomaly": 0.10,
    "hr_context_risk": 0.10,
    "temporal_anomaly": 0.06,
}

POSITIVE_LABELS = {"true_positive", "positive", "malicious", "high_risk"}
_MAX_REASON_CODES = 10


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, float(value)))


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _access_pattern_signal(event: dict) -> float:
    access = event.get("access") or {}
    off_hours_ratio = _clamp(_safe_float(access.get("off_hours_ratio")))
    frequency_z = _clamp(_safe_float(access.get("frequency_zscore")) / 4.0)
    sensitive_touches = _clamp(_safe_float(access.get("sensitive_resource_touches")) / 20.0)
    new_sensitive_targets = _clamp(_safe_float(access.get("new_sensitive_repos")) / 5.0)
    return _clamp(
        (0.35 * off_hours_ratio)
        + (0.30 * frequency_z)
        + (0.20 * sensitive_touches)
        + (0.15 * new_sensitive_targets)
    )


def _data_volume_signal(event: dict) -> float:
    data = event.get("data_movement") or {}
    download_gb = _safe_float(data.get("download_gb"))
    baseline_gb = max(0.25, _safe_float(data.get("baseline_gb"), default=1.0))
    download_ratio = _clamp((download_gb / baseline_gb - 1.0) / 6.0)
    usb_events = _clamp(_safe_float(data.get("usb_write_events")) / 8.0)
    cloud_upload_mb = _clamp(_safe_float(data.get("cloud_upload_mb")) / 20000.0)
    return _clamp((0.50 * download_ratio) + (0.25 * usb_events) + (0.25 * cloud_upload_mb))


def _physical_logical_signal(event: dict) -> float:
    physical = event.get("physical_logical") or {}
    badge_present = _as_bool(physical.get("badge_present"))
    missing_badge_logins = _clamp(_safe_float(physical.get("login_without_badge_count")) / 4.0)
    impossible_travel = _clamp(_safe_float(physical.get("impossible_travel_events")) / 2.0)
    after_hours_badge = _clamp(_safe_float(physical.get("after_hours_badge_swipes")) / 4.0)
    badge_alignment_penalty = 0.0 if badge_present and after_hours_badge > 0.0 else 1.0
    return _clamp(
        (0.45 * missing_badge_logins)
        + (0.40 * impossible_travel)
        + (0.15 * badge_alignment_penalty)
    )


def _hr_context_signal(event: dict) -> float:
    hr_flags = event.get("hr_flags") or {}
    pip = 1.0 if _as_bool(hr_flags.get("pip")) else 0.0
    resignation = 1.0 if _as_bool(hr_flags.get("resignation_pending")) else 0.0
    termination = 1.0 if _as_bool(hr_flags.get("termination_pending")) else 0.0
    return _clamp((0.25 * pip) + (0.35 * resignation) + (0.40 * termination))


def _communications_signal(event: dict) -> float:
    comms = event.get("communications") or {}
    after_hours_ratio = _clamp(_safe_float(comms.get("after_hours_ratio")))
    new_external_contacts = _safe_float(comms.get("new_external_contacts"))
    baseline_external_contacts = max(
        1.0, _safe_float(comms.get("external_contact_baseline"), default=1.0)
    )
    contacts_delta = _clamp((new_external_contacts / baseline_external_contacts - 1.0) / 6.0)
    encrypted_channels = _clamp(_safe_float(comms.get("new_encrypted_channels")) / 4.0)
    return _clamp((0.40 * after_hours_ratio) + (0.35 * contacts_delta) + (0.25 * encrypted_channels))


def _access_escalation_signal(event: dict) -> float:
    escalation = event.get("access_escalation") or {}
    privilege_changes = _clamp(_safe_float(escalation.get("privilege_change_events")) / 3.0)
    failed_admin = _clamp(_safe_float(escalation.get("failed_admin_attempts")) / 10.0)
    return _clamp((0.60 * privilege_changes) + (0.40 * failed_admin))


def _temporal_signal(event: dict) -> float:
    temporal = event.get("temporal") or {}
    weekend_sessions = _clamp(_safe_float(temporal.get("weekend_sessions")) / 4.0)
    overnight_sessions = _clamp(_safe_float(temporal.get("overnight_sessions")) / 6.0)
    return _clamp((0.45 * weekend_sessions) + (0.55 * overnight_sessions))


def _derive_taxonomy_hits(event: dict, signals: dict[str, float]) -> list[str]:
    provided = event.get("taxonomy") or {}
    taxonomy_hits = set()
    for key in (
        "pre_attack_reconnaissance",
        "data_staging",
        "exfiltration_indicators",
        "access_escalation",
        "temporal_anomalies",
    ):
        if _as_bool(provided.get(key)):
            taxonomy_hits.add(key)

    if signals["access_pattern_deviation"] >= 0.55:
        taxonomy_hits.add("pre_attack_reconnaissance")
    if signals["data_volume_anomaly"] >= 0.55:
        taxonomy_hits.add("data_staging")
    if signals["data_volume_anomaly"] >= 0.70 or signals["communication_metadata_anomaly"] >= 0.65:
        taxonomy_hits.add("exfiltration_indicators")
    if signals["access_escalation"] >= 0.50:
        taxonomy_hits.add("access_escalation")
    if signals["temporal_anomaly"] >= 0.45:
        taxonomy_hits.add("temporal_anomalies")

    return sorted(taxonomy_hits)


def _score_to_tier(score: float) -> str:
    if score >= 85.0:
        return "CRITICAL"
    if score >= 70.0:
        return "HIGH"
    if score >= 50.0:
        return "ELEVATED"
    return "LOW"


def _event_reason_codes(
    event: dict,
    signals: dict[str, float],
    taxonomy_hits: list[str],
    acceleration_factor: float,
    event_score: float,
) -> list[str]:
    codes = []
    if signals["access_pattern_deviation"] >= 0.65:
        codes.append("access_pattern_deviation_high")
    if signals["data_volume_anomaly"] >= 0.65:
        codes.append("data_volume_anomaly_high")
    if signals["physical_logical_mismatch"] >= 0.60:
        codes.append("badge_logical_mismatch")
    if signals["access_escalation"] >= 0.55:
        codes.append("access_escalation_signal")
    if signals["communication_metadata_anomaly"] >= 0.55:
        codes.append("communication_metadata_shift")
    if signals["hr_context_risk"] >= 0.50:
        codes.append("hr_context_stressor")
    if signals["temporal_anomaly"] >= 0.50:
        codes.append("off_hours_temporal_anomaly")

    hr_flags = event.get("hr_flags") or {}
    if _as_bool(hr_flags.get("termination_pending")):
        codes.append("hr_termination_pending")
    if _as_bool(hr_flags.get("resignation_pending")):
        codes.append("hr_resignation_pending")
    for hit in taxonomy_hits:
        codes.append(f"taxonomy_{hit}")
    if acceleration_factor >= 0.40:
        codes.append("cumulative_risk_acceleration")
    if event_score < 35.0 and not codes:
        codes.append("isolated_benign_anomaly")
    return sorted(dict.fromkeys(codes))[:_MAX_REASON_CODES]


def score_insider_event(event: dict) -> dict:
    signals = {
        "access_pattern_deviation": round(_access_pattern_signal(event), 4),
        "data_volume_anomaly": round(_data_volume_signal(event), 4),
        "physical_logical_mismatch": round(_physical_logical_signal(event), 4),
        "access_escalation": round(_access_escalation_signal(event), 4),
        "communication_metadata_anomaly": round(_communications_signal(event), 4),
        "hr_context_risk": round(_hr_context_signal(event), 4),
        "temporal_anomaly": round(_temporal_signal(event), 4),
    }
    weighted_signal_sum = 0.0
    for signal_name, weight in SIGNAL_WEIGHTS.items():
        weighted_signal_sum += weight * signals[signal_name]
    weighted_signal_sum = _clamp(weighted_signal_sum)

    prior_mean_irs = _safe_float(event.get("prior_30d_mean_irs"), default=0.0)
    high_signal_count = sum(1 for value in signals.values() if value >= 0.55)
    moderate_signal_count = sum(1 for value in signals.values() if 0.35 <= value < 0.55)
    high_signal_norm = _clamp(high_signal_count / max(1, len(signals)))
    moderate_signal_norm = _clamp(moderate_signal_count / max(1, len(signals)))
    trend_norm = (
        _clamp(((weighted_signal_sum * 100.0) - prior_mean_irs) / 35.0)
        if prior_mean_irs > 0.0
        else high_signal_norm
    )
    acceleration_factor = _clamp(
        (0.55 * high_signal_norm) + (0.20 * moderate_signal_norm) + (0.25 * trend_norm)
    )

    event_score = min(100.0, (weighted_signal_sum * 100.0) + (acceleration_factor * 12.0))
    event_score = round(event_score, 3)

    taxonomy_hits = _derive_taxonomy_hits(event, signals)
    reason_codes = _event_reason_codes(
        event=event,
        signals=signals,
        taxonomy_hits=taxonomy_hits,
        acceleration_factor=acceleration_factor,
        event_score=event_score,
    )

    return {
        "scenario_id": str(event.get("scenario_id") or "").strip(),
        "subject_id": str(event.get("subject_id") or "").strip(),
        "subject_name": str(event.get("subject_name") or "").strip(),
        "subject_handle": str(event.get("subject_handle") or "").strip(),
        "device_id": str(event.get("device_id") or "").strip(),
        "event_ts": str(event.get("event_ts") or "").strip(),
        "expected_label": str(event.get("expected_label") or "").strip().lower(),
        "signals": signals,
        "taxonomy_hits": taxonomy_hits,
        "acceleration_factor": round(acceleration_factor, 4),
        "event_score": event_score,
        "risk_tier": _score_to_tier(event_score),
        "reason_codes": reason_codes,
        "related_entities": event.get("related_entities") or [],
        "title": str(event.get("title") or "").strip(),
        "summary": str(event.get("summary") or "").strip(),
    }


def build_subject_assessments(scored_events: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for event in scored_events:
        subject_id = str(event.get("subject_id") or "").strip()
        if subject_id:
            grouped[subject_id].append(event)

    assessments = []
    for subject_id, events in grouped.items():
        events_sorted = sorted(events, key=lambda row: parse_timestamp(row.get("event_ts")) or row.get("event_ts"))
        scores = [float(event.get("event_score") or 0.0) for event in events_sorted]
        signal_means = {}
        for signal_name in SIGNAL_WEIGHTS.keys():
            signal_means[signal_name] = round(
                sum(float(event["signals"][signal_name]) for event in events_sorted) / max(1, len(events_sorted)),
                4,
            )

        latest_score = scores[-1]
        peak_score = max(scores)
        mean_score = sum(scores) / max(1, len(scores))
        prior_mean = sum(scores[:-1]) / len(scores[:-1]) if len(scores) > 1 else mean_score
        trend_norm = _clamp((latest_score - prior_mean) / 30.0)
        cumulative_low_signals = sum(1 for score in scores if 35.0 <= score < 70.0)
        low_signal_norm = _clamp(cumulative_low_signals / max(1, len(scores)))
        cumulative_boost = min(12.0, (trend_norm * 7.0) + (low_signal_norm * 5.0))
        irs_score = min(
            100.0,
            (0.35 * mean_score) + (0.40 * peak_score) + (0.25 * latest_score) + cumulative_boost,
        )
        irs_score = round(irs_score, 3)

        reason_counter = Counter()
        taxonomy_hits = set()
        for event in events_sorted:
            for reason_code in event.get("reason_codes", []):
                reason_counter[str(reason_code)] += 1
            for hit in event.get("taxonomy_hits", []):
                taxonomy_hits.add(str(hit))
        ordered_reasons = [code for code, _ in reason_counter.most_common(_MAX_REASON_CODES)]
        if cumulative_boost >= 3.0 and "cumulative_risk_acceleration" not in ordered_reasons:
            ordered_reasons.append("cumulative_risk_acceleration")
        ordered_reasons = ordered_reasons[:_MAX_REASON_CODES]

        latest_event = events_sorted[-1]
        assessments.append(
            {
                "subject_id": subject_id,
                "subject_name": latest_event.get("subject_name") or subject_id,
                "subject_handle": latest_event.get("subject_handle") or None,
                "irs_score": irs_score,
                "risk_tier": _score_to_tier(irs_score),
                "reason_codes": ordered_reasons,
                "signal_breakdown": signal_means,
                "taxonomy_hits": sorted(taxonomy_hits),
                "event_count": len(events_sorted),
                "latest_event_ts": latest_event.get("event_ts"),
            }
        )

    assessments.sort(key=lambda row: float(row.get("irs_score") or 0.0), reverse=True)
    return assessments


def upsert_insider_assessments(conn, assessments: list[dict]) -> None:
    for assessment in assessments:
        conn.execute(
            """INSERT INTO insider_risk_assessments
            (subject_id, subject_name, subject_handle, irs_score, risk_tier, reason_codes_json,
             signal_breakdown_json, taxonomy_hits_json, event_count, latest_event_ts, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(subject_id) DO UPDATE SET
                subject_name = excluded.subject_name,
                subject_handle = excluded.subject_handle,
                irs_score = excluded.irs_score,
                risk_tier = excluded.risk_tier,
                reason_codes_json = excluded.reason_codes_json,
                signal_breakdown_json = excluded.signal_breakdown_json,
                taxonomy_hits_json = excluded.taxonomy_hits_json,
                event_count = excluded.event_count,
                latest_event_ts = excluded.latest_event_ts,
                updated_at = CURRENT_TIMESTAMP""",
            (
                assessment["subject_id"],
                assessment["subject_name"],
                assessment.get("subject_handle"),
                float(assessment["irs_score"]),
                assessment["risk_tier"],
                json.dumps(assessment.get("reason_codes") or []),
                json.dumps(assessment.get("signal_breakdown") or {}),
                json.dumps(assessment.get("taxonomy_hits") or []),
                int(assessment.get("event_count") or 0),
                assessment.get("latest_event_ts"),
            ),
        )


def _parse_json(value: Any, fallback: Any):
    if value is None:
        return fallback
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def list_insider_risk(min_score: float = 0.0, limit: int = 100) -> list[dict]:
    safe_limit = max(1, min(int(limit), 500))
    safe_min_score = max(0.0, min(float(min_score), 100.0))
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT subject_id, subject_name, subject_handle, irs_score, risk_tier,
                      reason_codes_json, signal_breakdown_json, taxonomy_hits_json,
                      event_count, latest_event_ts, updated_at
            FROM insider_risk_assessments
            WHERE irs_score >= ?
            ORDER BY irs_score DESC, updated_at DESC
            LIMIT ?""",
            (safe_min_score, safe_limit),
        ).fetchall()
    finally:
        conn.close()

    payload = []
    for row in rows:
        item = dict(row)
        item["reason_codes"] = _parse_json(item.pop("reason_codes_json", None), [])
        item["signal_breakdown"] = _parse_json(item.pop("signal_breakdown_json", None), {})
        item["taxonomy_hits"] = _parse_json(item.pop("taxonomy_hits_json", None), [])
        payload.append(item)
    return payload


def evaluate_scored_events(scored_events: list[dict], threshold: float = 65.0) -> dict:
    safe_threshold = max(0.0, min(float(threshold), 100.0))
    tp = fp = fn = tn = 0
    rows = []
    for event in scored_events:
        expected_label = str(event.get("expected_label") or "").strip().lower()
        expected_positive = expected_label in POSITIVE_LABELS
        predicted_positive = float(event.get("event_score") or 0.0) >= safe_threshold

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
                "scenario_id": event.get("scenario_id"),
                "subject_id": event.get("subject_id"),
                "expected_positive": expected_positive,
                "predicted_positive": predicted_positive,
                "score": round(float(event.get("event_score") or 0.0), 3),
                "risk_tier": event.get("risk_tier"),
                "reason_codes": event.get("reason_codes") or [],
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
