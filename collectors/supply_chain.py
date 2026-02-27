"""Fixture-first supply-chain risk collector (env-gated)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from analytics.risk_scoring import score_to_severity
from analytics.supply_chain_risk import score_vendor_profile, upsert_supply_chain_assessments
from database.init_db import get_connection
from monitoring.collector_health import CollectorHealthObserver
from scraper.source_health import mark_source_failure, mark_source_skipped

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "supply_chain_scenarios.json"
SOURCE_NAME = "Supply Chain Risk (Fixture Scaffold)"


def _enabled():
    return os.getenv("PI_ENABLE_SUPPLY_CHAIN", "0").strip().lower() in {"1", "true", "yes", "on"}


def _load_fixtures():
    if not FIXTURE_PATH.exists():
        return []
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _ensure_source(conn):
    row = conn.execute(
        "SELECT id FROM sources WHERE source_type = 'supply_chain' AND name = ?",
        (SOURCE_NAME,),
    ).fetchone()
    if row:
        return int(row["id"])
    conn.execute(
        """INSERT INTO sources (name, url, source_type, credibility_score, active)
        VALUES (?, ?, ?, ?, 1)""",
        (SOURCE_NAME, "supply-chain://fixtures", "supply_chain", 0.6),
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


def collect_supply_chain():
    conn = get_connection()
    source_id = None
    created = 0
    try:
        observer = CollectorHealthObserver(conn, "supply_chain")
        source_id = _ensure_source(conn)
        if not _enabled():
            mark_source_skipped(conn, source_id, "PI_ENABLE_SUPPLY_CHAIN not set")
            conn.commit()
            print("Supply-chain collector skipped (PI_ENABLE_SUPPLY_CHAIN not set).")
            return 0

        profiles = _load_fixtures()
        if not profiles:
            mark_source_failure(conn, source_id, "supply chain fixtures missing or empty")
            conn.commit()
            print("Supply-chain collector skipped (no fixtures found).")
            return 0

        keyword_id = _ensure_keyword(conn)
        scored_profiles = []
        with observer.observe(source_id, collection_count=lambda: created):
            for profile in profiles:
                scored = score_vendor_profile(profile)
                if not scored.get("profile_id") or not scored.get("vendor_name"):
                    continue
                alert_id, is_new = _upsert_alert(conn, source_id, keyword_id, scored)
                _upsert_vendor_profile(conn, scored, source_alert_id=alert_id)
                _upsert_alert_entities(conn, alert_id, scored)
                scored_profiles.append(scored)
                if is_new:
                    created += 1

            upsert_supply_chain_assessments(conn, scored_profiles)
        conn.commit()
        print(f"Supply-chain collector complete. {created} new alerts.")
        return created
    except Exception as exc:
        conn.commit()
        print(f"Supply-chain collector failed: {exc}")
        return 0
    finally:
        conn.close()
