"""Fixture-first supply-chain risk collector (env-gated)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from analytics.risk_scoring import score_to_severity
from analytics.supply_chain_risk import score_vendor_profile, upsert_supply_chain_assessments
from analytics.utils import utcnow
from database.init_db import get_connection
from monitoring.collector_health import CollectorHealthObserver
from scraper.source_health import mark_source_failure, mark_source_skipped

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "supply_chain_scenarios.json"
SOURCE_NAME = "Supply Chain Risk (Fixture Scaffold)"
INGEST_SOURCE_NAME = "Supply Chain Risk (Ingest API)"


def _enabled():
    return os.getenv("PI_ENABLE_SUPPLY_CHAIN", "0").strip().lower() in {"1", "true", "yes", "on"}


def _load_fixtures():
    if not FIXTURE_PATH.exists():
        return []
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _coalesce(*values):
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _risk_to_privilege_scope(value):
    numeric = _safe_float(value)
    if numeric is None:
        return None
    if numeric >= 0.90:
        return "domain_admin"
    if numeric >= 0.70:
        return "admin"
    if numeric >= 0.40:
        return "moderate"
    return "limited"


def _risk_to_data_sensitivity(value):
    numeric = _safe_float(value)
    if numeric is None:
        return None
    if numeric >= 0.85:
        return "critical"
    if numeric >= 0.60:
        return "high"
    if numeric >= 0.35:
        return "moderate"
    return "low"


def _risk_to_compliance_posture(value):
    numeric = _safe_float(value)
    if numeric is None:
        return None
    if numeric >= 0.80:
        return "material_findings"
    if numeric >= 0.55:
        return "gaps"
    if numeric >= 0.30:
        return "adequate"
    return "strong"


def _risk_to_dependency_percent(value):
    numeric = _safe_float(value)
    if numeric is None:
        return None
    return max(0.0, min(100.0, round(float(numeric) * 100.0, 2)))


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _ensure_source(conn, source_name=SOURCE_NAME, source_url="supply-chain://fixtures"):
    row = conn.execute(
        "SELECT id FROM sources WHERE source_type = 'supply_chain' AND name = ?",
        (str(source_name),),
    ).fetchone()
    if row:
        return int(row["id"])
    conn.execute(
        """INSERT INTO sources (name, url, source_type, credibility_score, active)
        VALUES (?, ?, ?, ?, 1)""",
        (str(source_name), str(source_url), "supply_chain", 0.6),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def _ensure_keyword(conn):
    row = conn.execute("SELECT id FROM keywords WHERE term = ?", ("third party vendor risk",)).fetchone()
    if row:
        return int(row["id"])
    conn.execute(
        """INSERT INTO keywords (term, category, weight, active)
        VALUES (?, 'protective_intel', ?, 1)""",
        ("third party vendor risk", 3.2),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def _upsert_alert(conn, source_id, keyword_id, scored):
    profile_id = scored["profile_id"]
    url = f"supply-chain://profile/{profile_id}"
    score = float(scored["vendor_risk_score"])
    severity = score_to_severity(score)
    reasons = ", ".join(scored.get("reason_codes") or [])
    title = f"Vendor risk assessment: {scored['vendor_name']}"
    content = (
        f"country={scored.get('country') or 'unknown'} | "
        f"tier={scored.get('risk_tier')} | reason_codes={reasons}"
    )

    existing = conn.execute("SELECT id FROM alerts WHERE url = ?", (url,)).fetchone()
    if existing:
        alert_id = int(existing["id"])
        conn.execute(
            """UPDATE alerts
            SET source_id = ?,
                keyword_id = ?,
                title = ?,
                content = ?,
                matched_term = ?,
                published_at = CURRENT_TIMESTAMP,
                risk_score = ?,
                ors_score = ?,
                severity = ?,
                duplicate_of = NULL
            WHERE id = ?""",
            (
                source_id,
                keyword_id,
                title,
                content[:2000],
                "third party vendor risk",
                score,
                score,
                severity,
                alert_id,
            ),
        )
        return alert_id, False

    conn.execute(
        """INSERT INTO alerts
        (source_id, keyword_id, title, content, url, matched_term, published_at,
         risk_score, ors_score, severity, reviewed)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, 0)""",
        (
            source_id,
            keyword_id,
            title,
            content[:2000],
            url,
            "third party vendor risk",
            score,
            score,
            severity,
        ),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0]), True


def _upsert_vendor_profile(conn, scored, source_alert_id):
    conn.execute(
        """INSERT INTO supply_chain_vendor_profiles
        (profile_id, vendor_name, country, vendor_domain, expected_label, factors_json,
         source_alert_id, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(profile_id) DO UPDATE SET
            vendor_name = excluded.vendor_name,
            country = excluded.country,
            vendor_domain = excluded.vendor_domain,
            expected_label = excluded.expected_label,
            factors_json = excluded.factors_json,
            source_alert_id = excluded.source_alert_id,
            updated_at = CURRENT_TIMESTAMP""",
        (
            scored["profile_id"],
            scored["vendor_name"],
            scored.get("country"),
            scored.get("vendor_domain"),
            scored.get("expected_label"),
            json.dumps(scored.get("factors") or {}),
            int(source_alert_id),
        ),
    )


def _upsert_alert_entities(conn, alert_id, scored):
    vendor_domain = str(scored.get("vendor_domain") or "").strip().lower()
    if vendor_domain:
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'domain', ?, CURRENT_TIMESTAMP)""",
            (alert_id, vendor_domain),
        )

    vendor_id = str(scored.get("profile_id") or "").strip().lower()
    if vendor_id:
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'vendor_id', ?, CURRENT_TIMESTAMP)""",
            (alert_id, vendor_id),
        )

    vendor_name = str(scored.get("vendor_name") or "").strip().lower()
    if vendor_name:
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'vendor_name', ?, CURRENT_TIMESTAMP)""",
            (alert_id, vendor_name),
        )


def _normalize_profile(raw_profile, idx):
    if not isinstance(raw_profile, dict):
        return None

    factors = raw_profile.get("factors")
    if not isinstance(factors, dict):
        factors = {}

    vendor_name = str(raw_profile.get("vendor_name") or raw_profile.get("name") or "").strip()
    if not vendor_name:
        return None

    vendor_domain = str(raw_profile.get("vendor_domain") or raw_profile.get("domain") or "").strip().lower()
    profile_id = str(
        raw_profile.get("profile_id") or raw_profile.get("vendor_id") or raw_profile.get("external_id") or ""
    ).strip()
    if not profile_id:
        profile_id = f"ing-vendor-{idx}-{vendor_name.lower().replace(' ', '-')[:24]}"

    normalized = dict(raw_profile)
    normalized["vendor_name"] = vendor_name
    normalized["vendor_domain"] = vendor_domain
    normalized["profile_id"] = profile_id
    normalized["country"] = str(
        raw_profile.get("country") or raw_profile.get("country_code") or ""
    ).strip().upper()
    normalized["single_point_of_failure"] = _as_bool(
        _coalesce(
            raw_profile.get("single_point_of_failure"),
            factors.get("single_point_of_failure"),
            (_safe_float(factors.get("single_point_of_failure_concentration")) or 0.0) >= 0.65,
            (_safe_float(factors.get("concentration_risk")) or 0.0) >= 0.65,
        )
    )
    normalized["critical_dependency_percent"] = _coalesce(
        raw_profile.get("critical_dependency_percent"),
        factors.get("critical_dependency_percent"),
        factors.get("single_point_dependency_percent"),
        _risk_to_dependency_percent(factors.get("single_point_of_failure_concentration")),
        _risk_to_dependency_percent(factors.get("concentration_risk")),
        30.0,
    )
    normalized["privilege_scope"] = str(
        _coalesce(
            raw_profile.get("privilege_scope"),
            factors.get("privilege_scope"),
            _risk_to_privilege_scope(factors.get("privilege_scope_risk")),
            _risk_to_privilege_scope(factors.get("access_privilege_scope")),
            "moderate",
        )
    ).strip().lower()
    normalized["data_sensitivity"] = str(
        _coalesce(
            raw_profile.get("data_sensitivity"),
            factors.get("data_sensitivity"),
            _risk_to_data_sensitivity(factors.get("data_exposure_risk")),
            _risk_to_data_sensitivity(factors.get("data_sensitivity_exposure")),
            "moderate",
        )
    ).strip().lower()
    normalized["compliance_posture"] = str(
        _coalesce(
            raw_profile.get("compliance_posture"),
            factors.get("compliance_posture"),
            _risk_to_compliance_posture(factors.get("compliance_posture_risk")),
            _risk_to_compliance_posture(factors.get("compliance_posture_indicators")),
            "adequate",
        )
    ).strip().lower()
    normalized["recent_incidents"] = _coalesce(
        raw_profile.get("recent_incidents"),
        factors.get("recent_incidents"),
        0,
    )
    normalized["expected_label"] = str(raw_profile.get("expected_label") or "").strip().lower()
    normalized["ingested_at"] = utcnow().strftime("%Y-%m-%d %H:%M:%S")
    return normalized


def ingest_supply_chain_profiles(
    profiles,
    source_name=INGEST_SOURCE_NAME,
    source_url="supply-chain://ingest-api",
    observer_name="supply_chain_ingest",
):
    conn = get_connection()
    source_id = None
    created = 0
    updated = 0
    invalid = 0
    try:
        observer = CollectorHealthObserver(conn, observer_name)
        source_id = _ensure_source(conn, source_name=source_name, source_url=source_url)
        keyword_id = _ensure_keyword(conn)
        scored_profiles = []
        with observer.observe(source_id, collection_count=lambda: created + updated):
            for idx, raw_profile in enumerate(profiles or []):
                normalized = _normalize_profile(raw_profile, idx)
                if normalized is None:
                    invalid += 1
                    continue
                scored = score_vendor_profile(normalized)
                if not scored.get("profile_id") or not scored.get("vendor_name"):
                    invalid += 1
                    continue
                alert_id, is_new = _upsert_alert(conn, source_id, keyword_id, scored)
                _upsert_vendor_profile(conn, scored, source_alert_id=alert_id)
                _upsert_alert_entities(conn, alert_id, scored)
                scored_profiles.append(scored)
                if is_new:
                    created += 1
                else:
                    updated += 1

            upsert_supply_chain_assessments(conn, scored_profiles)
        conn.commit()
        return {
            "processed": len(profiles or []),
            "ingested": created,
            "updated": updated,
            "invalid": invalid,
            "profiles_scored": len(scored_profiles),
        }
    finally:
        conn.close()


def collect_supply_chain():
    if not _enabled():
        conn = get_connection()
        try:
            source_id = _ensure_source(conn, source_name=SOURCE_NAME, source_url="supply-chain://fixtures")
            mark_source_skipped(conn, source_id, "PI_ENABLE_SUPPLY_CHAIN not set")
            conn.commit()
        finally:
            conn.close()
        print("Supply-chain collector skipped (PI_ENABLE_SUPPLY_CHAIN not set).")
        return 0

    profiles = _load_fixtures()
    if not profiles:
        conn = get_connection()
        try:
            source_id = _ensure_source(conn, source_name=SOURCE_NAME, source_url="supply-chain://fixtures")
            mark_source_failure(conn, source_id, "supply chain fixtures missing or empty")
            conn.commit()
        finally:
            conn.close()
        print("Supply-chain collector skipped (no fixtures found).")
        return 0

    try:
        stats = ingest_supply_chain_profiles(
            profiles,
            source_name=SOURCE_NAME,
            source_url="supply-chain://fixtures",
            observer_name="supply_chain_fixture",
        )
        print(
            "Supply-chain collector complete. "
            f"{stats['ingested']} new alerts, {stats['updated']} updated."
        )
        return int(stats["ingested"])
    except Exception as exc:
        conn = get_connection()
        try:
            source_id = _ensure_source(conn, source_name=SOURCE_NAME, source_url="supply-chain://fixtures")
            mark_source_failure(conn, source_id, f"supply-chain collector failed: {exc!r}")
            conn.commit()
        finally:
            conn.close()
        print(f"Supply-chain collector failed: {exc}")
        return 0
