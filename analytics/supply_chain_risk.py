"""Supply-chain risk scoring scaffold for vendor profiles."""

from __future__ import annotations

import json
from typing import Any

from database.init_db import get_connection

COUNTRY_RISK = {
    "US": 0.10,
    "CA": 0.12,
    "GB": 0.18,
    "DE": 0.20,
    "AU": 0.18,
    "IN": 0.35,
    "MX": 0.30,
    "BR": 0.40,
    "TR": 0.45,
    "CN": 0.65,
    "RU": 0.85,
    "IR": 0.90,
    "KP": 0.95,
}

PRIVILEGE_RISK = {
    "limited": 0.20,
    "moderate": 0.45,
    "admin": 0.75,
    "domain_admin": 0.95,
}

DATA_SENSITIVITY_RISK = {
    "low": 0.20,
    "moderate": 0.45,
    "high": 0.75,
    "critical": 0.95,
}

COMPLIANCE_RISK = {
    "strong": 0.15,
    "adequate": 0.35,
    "gaps": 0.65,
    "material_findings": 0.90,
}

VENDOR_WEIGHTS = {
    "geographic_risk": 0.25,
    "concentration_risk": 0.20,
    "privilege_scope_risk": 0.20,
    "data_exposure_risk": 0.20,
    "compliance_posture_risk": 0.15,
}


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


def _score_to_tier(score: float) -> str:
    if score >= 80.0:
        return "HIGH"
    if score >= 60.0:
        return "ELEVATED"
    if score >= 40.0:
        return "GUARDED"
    return "LOW"


def _build_reason_codes(factors: dict[str, float], incidents: int) -> list[str]:
    reason_codes = []
    if factors["geographic_risk"] >= 0.60:
        reason_codes.append("geographic_exposure_high")
    if factors["concentration_risk"] >= 0.60:
        reason_codes.append("single_point_of_failure")
    if factors["privilege_scope_risk"] >= 0.70:
        reason_codes.append("privilege_scope_broad")
    if factors["data_exposure_risk"] >= 0.70:
        reason_codes.append("sensitive_data_exposure")
    if factors["compliance_posture_risk"] >= 0.60:
        reason_codes.append("compliance_posture_gap")
    if incidents >= 2:
        reason_codes.append("recent_incident_history")
    if not reason_codes:
        reason_codes.append("baseline_monitoring")
    return reason_codes


def score_vendor_profile(profile: dict) -> dict:
    country = str(profile.get("country") or "").strip().upper()
    privilege_scope = str(profile.get("privilege_scope") or "moderate").strip().lower()
    data_sensitivity = str(profile.get("data_sensitivity") or "moderate").strip().lower()
    compliance_posture = str(profile.get("compliance_posture") or "adequate").strip().lower()
    incidents = int(max(0.0, _safe_float(profile.get("recent_incidents"), default=0.0)))

    geographic_risk = COUNTRY_RISK.get(country, 0.40)
    dependency_pct = _clamp(_safe_float(profile.get("critical_dependency_percent")) / 100.0)
    single_point = _as_bool(profile.get("single_point_of_failure"))
    concentration_risk = _clamp((0.65 if single_point else 0.25) + (0.35 * dependency_pct))
    privilege_scope_risk = PRIVILEGE_RISK.get(privilege_scope, 0.45)
    data_exposure_risk = DATA_SENSITIVITY_RISK.get(data_sensitivity, 0.45)
    compliance_posture_risk = COMPLIANCE_RISK.get(compliance_posture, 0.35)

    factors = {
        "geographic_risk": round(geographic_risk, 4),
        "concentration_risk": round(concentration_risk, 4),
        "privilege_scope_risk": round(privilege_scope_risk, 4),
        "data_exposure_risk": round(data_exposure_risk, 4),
        "compliance_posture_risk": round(compliance_posture_risk, 4),
    }

    weighted = 0.0
    for factor_name, weight in VENDOR_WEIGHTS.items():
        weighted += weight * factors[factor_name]
    incident_modifier = min(10.0, incidents * 2.5)
    risk_score = min(100.0, (weighted * 100.0) + incident_modifier)
    risk_score = round(risk_score, 3)

    return {
        "profile_id": str(profile.get("profile_id") or "").strip(),
        "vendor_name": str(profile.get("vendor_name") or "").strip(),
        "country": country,
        "vendor_domain": str(profile.get("vendor_domain") or "").strip().lower(),
        "expected_label": str(profile.get("expected_label") or "").strip().lower(),
        "factors": factors,
        "reason_codes": _build_reason_codes(factors, incidents=incidents),
        "vendor_risk_score": risk_score,
        "risk_tier": _score_to_tier(risk_score),
        "raw_profile": profile,
    }


def upsert_supply_chain_assessments(conn, scored_profiles: list[dict]) -> None:
    for scored in scored_profiles:
        conn.execute(
            """INSERT INTO supply_chain_risk_assessments
            (profile_id, vendor_name, country, vendor_domain, vendor_risk_score, risk_tier,
             reason_codes_json, factor_breakdown_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(profile_id) DO UPDATE SET
                vendor_name = excluded.vendor_name,
                country = excluded.country,
                vendor_domain = excluded.vendor_domain,
                vendor_risk_score = excluded.vendor_risk_score,
                risk_tier = excluded.risk_tier,
                reason_codes_json = excluded.reason_codes_json,
                factor_breakdown_json = excluded.factor_breakdown_json,
                updated_at = CURRENT_TIMESTAMP""",
            (
                scored["profile_id"],
                scored["vendor_name"],
                scored["country"],
                scored.get("vendor_domain"),
                float(scored["vendor_risk_score"]),
                scored["risk_tier"],
                json.dumps(scored.get("reason_codes") or []),
                json.dumps(scored.get("factors") or {}),
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


def list_supply_chain_risk(min_score: float = 0.0, limit: int = 100) -> list[dict]:
    safe_limit = max(1, min(int(limit), 500))
    safe_min_score = max(0.0, min(float(min_score), 100.0))

    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT profile_id, vendor_name, country, vendor_domain, vendor_risk_score, risk_tier,
                      reason_codes_json, factor_breakdown_json, updated_at
            FROM supply_chain_risk_assessments
            WHERE vendor_risk_score >= ?
            ORDER BY vendor_risk_score DESC, updated_at DESC
            LIMIT ?""",
            (safe_min_score, safe_limit),
        ).fetchall()
    finally:
        conn.close()

    payload = []
    for row in rows:
        item = dict(row)
        item["reason_codes"] = _parse_json(item.pop("reason_codes_json", None), [])
        item["factor_breakdown"] = _parse_json(item.pop("factor_breakdown_json", None), {})
        payload.append(item)
    return payload
