"""Fixture-first insider telemetry collector and IRS assessment updater."""

from __future__ import annotations

import json
from pathlib import Path

from analytics.insider_risk import (
    build_subject_assessments,
    score_insider_event,
    upsert_insider_assessments,
)
from analytics.risk_scoring import score_to_severity
from database.init_db import get_connection
from monitoring.collector_health import CollectorHealthObserver
from scraper.source_health import mark_source_failure

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "insider_scenarios.json"
SOURCE_NAME = "Insider Telemetry (Fixture UEBA)"


def _load_fixtures():
    if not FIXTURE_PATH.exists():
        return []
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _ensure_source(conn):
    row = conn.execute(
        "SELECT id FROM sources WHERE source_type = 'insider' AND name = ?",
        (SOURCE_NAME,),
    ).fetchone()
    if row:
        return int(row["id"])
    conn.execute(
        """INSERT INTO sources (name, url, source_type, credibility_score, active)
        VALUES (?, ?, ?, ?, 1)""",
        (SOURCE_NAME, "insider://fixtures", "insider", 0.75),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def _ensure_keyword(conn):
    row = conn.execute(
        "SELECT id FROM keywords WHERE term = ?",
        ("insider telemetry anomaly",),
    ).fetchone()
    if row:
        return int(row["id"])
    conn.execute(
        """INSERT INTO keywords (term, category, weight, active)
        VALUES (?, 'insider_workplace', ?, 1)""",
        ("insider telemetry anomaly", 3.8),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def _alert_title(scored_event):
    title = str(scored_event.get("title") or "").strip()
    if title:
        return title
    subject_name = scored_event.get("subject_name") or scored_event.get("subject_id")
    return f"Insider telemetry anomaly: {subject_name}"


def _alert_content(scored_event):
    summary = str(scored_event.get("summary") or "").strip()
    taxonomy = ", ".join(scored_event.get("taxonomy_hits") or [])
    reasons = ", ".join(scored_event.get("reason_codes") or [])
    lines = []
    if summary:
        lines.append(summary)
    if taxonomy:
        lines.append(f"taxonomy={taxonomy}")
    if reasons:
        lines.append(f"reason_codes={reasons}")
    return " | ".join(lines)[:2000]


def _upsert_alert(conn, source_id, keyword_id, scored_event):
    scenario_id = scored_event["scenario_id"]
    url = f"insider://scenario/{scenario_id}"
    score = float(scored_event["event_score"])
    severity = score_to_severity(score)
    published_at = scored_event.get("event_ts")

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
                published_at = ?,
                risk_score = ?,
                ors_score = ?,
                severity = ?,
                duplicate_of = NULL
            WHERE id = ?""",
            (
                source_id,
                keyword_id,
                _alert_title(scored_event),
                _alert_content(scored_event),
                "insider telemetry anomaly",
                published_at,
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
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
        (
            source_id,
            keyword_id,
            _alert_title(scored_event),
            _alert_content(scored_event),
            url,
            "insider telemetry anomaly",
            published_at,
            score,
            score,
            severity,
        ),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0]), True


def _upsert_alert_entities(conn, alert_id, scored_event):
    subject_handle = str(scored_event.get("subject_handle") or "").strip().lower()
    if subject_handle:
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'actor_handle', ?, CURRENT_TIMESTAMP)""",
            (alert_id, subject_handle),
        )

    subject_id = str(scored_event.get("subject_id") or "").strip().lower()
    if subject_id:
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'insider_subject', ?, CURRENT_TIMESTAMP)""",
            (alert_id, subject_id),
        )
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'user_id', ?, CURRENT_TIMESTAMP)""",
            (alert_id, subject_id),
        )

    device_id = str(scored_event.get("device_id") or "").strip().lower()
    if device_id:
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'device_id', ?, CURRENT_TIMESTAMP)""",
            (alert_id, device_id),
        )

    for entity in scored_event.get("related_entities") or []:
        entity_type = str(entity.get("entity_type") or "").strip().lower()
        entity_value = str(entity.get("entity_value") or "").strip().lower()
        if entity_type not in {"domain", "ipv4", "url", "email", "user_id", "device_id", "vendor_id"} or not entity_value:
            continue
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)""",
            (alert_id, entity_type, entity_value),
        )


def _upsert_event_row(conn, scored_event, source_alert_id):
    conn.execute(
        """INSERT INTO insider_telemetry_events
        (scenario_id, subject_id, subject_name, subject_handle, event_ts, event_score,
         expected_label, taxonomy_json, signal_json, reason_codes_json,
         related_entities_json, source_alert_id, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(scenario_id) DO UPDATE SET
            subject_id = excluded.subject_id,
            subject_name = excluded.subject_name,
            subject_handle = excluded.subject_handle,
            event_ts = excluded.event_ts,
            event_score = excluded.event_score,
            expected_label = excluded.expected_label,
            taxonomy_json = excluded.taxonomy_json,
            signal_json = excluded.signal_json,
            reason_codes_json = excluded.reason_codes_json,
            related_entities_json = excluded.related_entities_json,
            source_alert_id = excluded.source_alert_id,
            updated_at = CURRENT_TIMESTAMP""",
        (
            scored_event["scenario_id"],
            scored_event["subject_id"],
            scored_event["subject_name"],
            scored_event.get("subject_handle"),
            scored_event.get("event_ts"),
            float(scored_event["event_score"]),
            scored_event.get("expected_label"),
            json.dumps(scored_event.get("taxonomy_hits") or []),
            json.dumps(scored_event.get("signals") or {}),
            json.dumps(scored_event.get("reason_codes") or []),
            json.dumps(scored_event.get("related_entities") or []),
            int(source_alert_id),
        ),
    )


def collect_insider_telemetry():
    conn = get_connection()
    created = 0
    source_id = None
    try:
        observer = CollectorHealthObserver(conn, "insider")
        source_id = _ensure_source(conn)
        fixtures = _load_fixtures()
        if not fixtures:
            mark_source_failure(conn, source_id, "insider fixtures missing or empty")
            conn.commit()
            print("Insider telemetry collector skipped (no fixtures found).")
            return 0

        keyword_id = _ensure_keyword(conn)
        scored_events = []
        with observer.observe(source_id, collection_count=lambda: created):
            for event in fixtures:
                scored = score_insider_event(event)
                if not scored.get("scenario_id") or not scored.get("subject_id"):
                    continue
                alert_id, is_new = _upsert_alert(conn, source_id, keyword_id, scored)
                _upsert_alert_entities(conn, alert_id, scored)
                _upsert_event_row(conn, scored, source_alert_id=alert_id)
                scored_events.append(scored)
                if is_new:
                    created += 1

            assessments = build_subject_assessments(scored_events)
            upsert_insider_assessments(conn, assessments)
        conn.commit()
        print(f"Insider telemetry collector complete. {created} new alerts.")
        return created
    except Exception as exc:
        conn.commit()
        print(f"Insider telemetry collector failed: {exc}")
        return 0
    finally:
        conn.close()
