"""Fixture-first insider telemetry collector and IRS assessment updater."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from analytics.insider_risk import (
    build_subject_assessments,
    score_insider_event,
    upsert_insider_assessments,
)
from analytics.risk_scoring import score_to_severity
from analytics.utils import utcnow
from database.init_db import get_connection
from monitoring.collector_health import CollectorHealthObserver
from scraper.source_health import mark_source_failure

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "insider_scenarios.json"
SOURCE_NAME = "Insider Telemetry (Fixture UEBA)"
INGEST_SOURCE_NAME = "Insider Telemetry (Ingest API)"


def _load_fixtures():
    if not FIXTURE_PATH.exists():
        return []
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _ensure_source(conn, source_name=SOURCE_NAME, source_url="insider://fixtures"):
    row = conn.execute(
        "SELECT id FROM sources WHERE source_type = 'insider' AND name = ?",
        (str(source_name),),
    ).fetchone()
    if row:
        return int(row["id"])
    conn.execute(
        """INSERT INTO sources (name, url, source_type, credibility_score, active)
        VALUES (?, ?, ?, ?, 1)""",
        (str(source_name), str(source_url), "insider", 0.75),
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


def _scaled(value, factor):
    numeric = _safe_float(value)
    if numeric is None:
        return None
    return numeric * float(factor)


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _normalize_event(raw_event, idx):
    if not isinstance(raw_event, dict):
        return None

    subject_id = str(raw_event.get("subject_id") or raw_event.get("user_id") or "").strip()
    if not subject_id:
        return None

    subject_name = str(raw_event.get("subject_name") or raw_event.get("user_name") or subject_id).strip()
    event_ts = (
        str(raw_event.get("event_ts") or raw_event.get("timestamp") or "").strip()
        or utcnow().strftime("%Y-%m-%d %H:%M:%S")
    )
    scenario_id = str(raw_event.get("scenario_id") or raw_event.get("event_id") or "").strip()
    if not scenario_id:
        digest = hashlib.sha256(
            f"{subject_id}|{event_ts}|{raw_event.get('title') or ''}|{idx}".encode("utf-8")
        ).hexdigest()[:16]
        scenario_id = f"ing-{digest}"

    normalized = dict(raw_event)
    signals = _as_dict(raw_event.get("signals"))
    access = _as_dict(raw_event.get("access"))
    data_movement = _as_dict(raw_event.get("data_movement"))
    physical_logical = _as_dict(raw_event.get("physical_logical"))
    hr_flags = _as_dict(raw_event.get("hr_flags"))
    communications = _as_dict(raw_event.get("communications"))
    access_escalation = _as_dict(raw_event.get("access_escalation"))
    temporal = _as_dict(raw_event.get("temporal"))
    taxonomy = _as_dict(raw_event.get("taxonomy"))

    access_pattern_deviation = _coalesce(
        signals.get("access_pattern_deviation"),
        raw_event.get("access_pattern_deviation"),
    )
    data_volume_anomaly = _coalesce(
        signals.get("data_volume_anomaly"),
        raw_event.get("data_volume_anomaly"),
    )
    physical_logical_mismatch = _coalesce(
        signals.get("physical_logical_mismatch"),
        raw_event.get("physical_logical_mismatch"),
    )
    escalation_signal = _coalesce(signals.get("access_escalation"), raw_event.get("access_escalation_signal"))
    comms_signal = _coalesce(
        signals.get("communication_metadata_anomaly"),
        signals.get("communication_metadata_shift"),
        raw_event.get("communication_metadata_shift"),
    )
    hr_signal = _coalesce(signals.get("hr_context_risk"), raw_event.get("hr_context_risk"))
    temporal_signal = _coalesce(signals.get("temporal_anomaly"), raw_event.get("temporal_anomaly"))

    download_gb = _coalesce(
        data_movement.get("download_gb"),
        raw_event.get("download_gb"),
        raw_event.get("bulk_data_download_gb"),
        signals.get("download_gb"),
        signals.get("bulk_data_download_gb"),
        _scaled(data_volume_anomaly, 12.0),
    )
    baseline_gb = _coalesce(
        data_movement.get("baseline_gb"),
        raw_event.get("baseline_gb"),
        signals.get("download_baseline_gb"),
        signals.get("baseline_gb"),
    )
    baseline_numeric = _safe_float(baseline_gb)
    if baseline_numeric is None or baseline_numeric <= 0:
        baseline_numeric = max(1.0, (_safe_float(download_gb) or 1.0) / 4.0)
    cloud_upload_mb = _coalesce(
        data_movement.get("cloud_upload_mb"),
        raw_event.get("cloud_upload_mb"),
        signals.get("cloud_upload_mb"),
        _scaled(raw_event.get("cloud_upload_gb"), 1024.0),
        _scaled(signals.get("cloud_upload_gb"), 1024.0),
        _scaled(data_volume_anomaly, 14000.0),
    )
    usb_write_events = _coalesce(
        data_movement.get("usb_write_events"),
        raw_event.get("usb_write_events"),
        signals.get("usb_write_events"),
        _scaled(raw_event.get("usb_write_gb"), 0.8),
        _scaled(signals.get("usb_write_gb"), 0.8),
    )
    badge_mismatch = _coalesce(
        physical_logical.get("login_without_badge_count"),
        raw_event.get("badge_login_mismatch"),
        signals.get("badge_login_mismatch"),
        _scaled(physical_logical_mismatch, 4.0),
    )
    off_hours = _coalesce(
        access.get("off_hours_ratio"),
        raw_event.get("off_hours_ratio"),
        signals.get("off_hours_activity"),
        access_pattern_deviation,
        temporal_signal,
    )
    sensitivity_access = _coalesce(
        access.get("sensitive_resource_touches"),
        raw_event.get("sensitive_resource_touches"),
        _scaled(signals.get("resource_sensitivity_access"), 20.0),
    )
    new_external_contacts = _coalesce(
        communications.get("new_external_contacts"),
        raw_event.get("new_external_contacts"),
        signals.get("new_external_contacts"),
        _scaled(comms_signal, 10.0),
    )

    normalized["access"] = {
        "off_hours_ratio": _coalesce(off_hours, 0.0),
        "frequency_zscore": _coalesce(
            access.get("frequency_zscore"),
            raw_event.get("access_frequency_zscore"),
            signals.get("access_frequency_zscore"),
            _scaled(access_pattern_deviation, 4.0),
            0.0,
        ),
        "sensitive_resource_touches": _coalesce(sensitivity_access, 0.0),
        "new_sensitive_repos": _coalesce(
            access.get("new_sensitive_repos"),
            raw_event.get("new_sensitive_repos"),
            signals.get("new_sensitive_repos"),
            _scaled(access_pattern_deviation, 3.0),
            0.0,
        ),
    }
    normalized["data_movement"] = {
        "download_gb": _coalesce(download_gb, 0.0),
        "baseline_gb": round(float(baseline_numeric), 4),
        "usb_write_events": _coalesce(usb_write_events, 0.0),
        "cloud_upload_mb": _coalesce(cloud_upload_mb, 0.0),
    }
    normalized["physical_logical"] = {
        "badge_present": _coalesce(
            physical_logical.get("badge_present"),
            raw_event.get("badge_present"),
            False if (_safe_float(badge_mismatch) or 0.0) > 0.1 else True,
        ),
        "login_without_badge_count": _coalesce(badge_mismatch, 0.0),
        "impossible_travel_events": _coalesce(
            physical_logical.get("impossible_travel_events"),
            raw_event.get("impossible_travel_events"),
            signals.get("impossible_travel_events"),
            _scaled(physical_logical_mismatch, 2.0),
            0.0,
        ),
        "after_hours_badge_swipes": _coalesce(
            physical_logical.get("after_hours_badge_swipes"),
            raw_event.get("after_hours_badge_swipes"),
            signals.get("after_hours_badge_swipes"),
            0.0,
        ),
    }
    normalized["hr_flags"] = {
        "pip": _coalesce(
            hr_flags.get("pip"),
            raw_event.get("pip"),
            raw_event.get("pip_flag"),
            signals.get("pip"),
            signals.get("hr_pip_flag"),
            (_safe_float(hr_signal) or 0.0) >= 0.4,
        ),
        "resignation_pending": _coalesce(
            hr_flags.get("resignation_pending"),
            raw_event.get("resignation_pending"),
            signals.get("resignation_pending"),
            False,
        ),
        "termination_pending": _coalesce(
            hr_flags.get("termination_pending"),
            raw_event.get("termination_pending"),
            signals.get("termination_pending"),
            False,
        ),
    }
    normalized["communications"] = {
        "after_hours_ratio": _coalesce(
            communications.get("after_hours_ratio"),
            raw_event.get("comm_after_hours_ratio"),
            signals.get("communication_after_hours_ratio"),
            comms_signal,
            off_hours,
            0.0,
        ),
        "new_external_contacts": _coalesce(new_external_contacts, 0.0),
        "external_contact_baseline": _coalesce(
            communications.get("external_contact_baseline"),
            raw_event.get("external_contact_baseline"),
            signals.get("external_contact_baseline"),
            1.0,
        ),
        "new_encrypted_channels": _coalesce(
            communications.get("new_encrypted_channels"),
            raw_event.get("new_encrypted_channels"),
            signals.get("new_encrypted_channels"),
            _scaled(comms_signal, 3.0),
            0.0,
        ),
    }
    normalized["access_escalation"] = {
        "privilege_change_events": _coalesce(
            access_escalation.get("privilege_change_events"),
            raw_event.get("privilege_change_events"),
            signals.get("privilege_change_events"),
            _scaled(escalation_signal, 3.0),
            0.0,
        ),
        "failed_admin_attempts": _coalesce(
            access_escalation.get("failed_admin_attempts"),
            raw_event.get("failed_admin_attempts"),
            signals.get("failed_admin_attempts"),
            _scaled(escalation_signal, 10.0),
            0.0,
        ),
    }
    normalized["temporal"] = {
        "weekend_sessions": _coalesce(
            temporal.get("weekend_sessions"),
            raw_event.get("weekend_sessions"),
            signals.get("weekend_sessions"),
            _scaled(temporal_signal, 4.0),
            0.0,
        ),
        "overnight_sessions": _coalesce(
            temporal.get("overnight_sessions"),
            raw_event.get("overnight_sessions"),
            signals.get("overnight_sessions"),
            _scaled(off_hours, 6.0),
            _scaled(temporal_signal, 6.0),
            0.0,
        ),
    }
    normalized["taxonomy"] = {
        "pre_attack_reconnaissance": _coalesce(
            taxonomy.get("pre_attack_reconnaissance"),
            signals.get("pre_attack_reconnaissance"),
            (_safe_float(access_pattern_deviation) or 0.0) >= 0.55,
        ),
        "data_staging": _coalesce(
            taxonomy.get("data_staging"),
            signals.get("data_staging"),
            (_safe_float(data_volume_anomaly) or 0.0) >= 0.55,
        ),
        "exfiltration_indicators": _coalesce(
            taxonomy.get("exfiltration_indicators"),
            signals.get("exfiltration_indicators"),
            (_safe_float(data_volume_anomaly) or 0.0) >= 0.7,
        ),
        "access_escalation": _coalesce(
            taxonomy.get("access_escalation"),
            signals.get("taxonomy_access_escalation"),
            (_safe_float(escalation_signal) or 0.0) >= 0.5,
        ),
        "temporal_anomalies": _coalesce(
            taxonomy.get("temporal_anomalies"),
            signals.get("temporal_anomalies"),
            (_safe_float(temporal_signal) or 0.0) >= 0.45,
        ),
    }

    normalized["subject_id"] = subject_id
    normalized["subject_name"] = subject_name
    normalized["event_ts"] = event_ts
    normalized["scenario_id"] = scenario_id
    normalized["device_id"] = str(
        raw_event.get("device_id") or raw_event.get("host_id") or ""
    ).strip()
    related_entities = raw_event.get("related_entities")
    normalized["related_entities"] = related_entities if isinstance(related_entities, list) else []
    return normalized


def ingest_insider_events(
    events,
    source_name=INGEST_SOURCE_NAME,
    source_url="insider://ingest-api",
    observer_name="insider_ingest",
):
    conn = get_connection()
    created = 0
    updated = 0
    invalid = 0
    source_id = None
    try:
        observer = CollectorHealthObserver(conn, observer_name)
        source_id = _ensure_source(conn, source_name=source_name, source_url=source_url)
        keyword_id = _ensure_keyword(conn)
        scored_events = []

        with observer.observe(source_id, collection_count=lambda: created + updated):
            for idx, raw_event in enumerate(events or []):
                normalized = _normalize_event(raw_event, idx)
                if normalized is None:
                    invalid += 1
                    continue
                scored = score_insider_event(normalized)
                if not scored.get("scenario_id") or not scored.get("subject_id"):
                    invalid += 1
                    continue
                alert_id, is_new = _upsert_alert(conn, source_id, keyword_id, scored)
                _upsert_alert_entities(conn, alert_id, scored)
                _upsert_event_row(conn, scored, source_alert_id=alert_id)
                scored_events.append(scored)
                if is_new:
                    created += 1
                else:
                    updated += 1

            assessments = build_subject_assessments(scored_events)
            upsert_insider_assessments(conn, assessments)
        conn.commit()
        return {
            "processed": len(events or []),
            "ingested": created,
            "updated": updated,
            "invalid": invalid,
            "subjects_assessed": len(build_subject_assessments(scored_events)),
        }
    finally:
        conn.close()


def collect_insider_telemetry():
    fixtures = _load_fixtures()
    if not fixtures:
        conn = get_connection()
        try:
            source_id = _ensure_source(conn, source_name=SOURCE_NAME, source_url="insider://fixtures")
            mark_source_failure(conn, source_id, "insider fixtures missing or empty")
            conn.commit()
        finally:
            conn.close()
        print("Insider telemetry collector skipped (no fixtures found).")
        return 0

    try:
        stats = ingest_insider_events(
            fixtures,
            source_name=SOURCE_NAME,
            source_url="insider://fixtures",
            observer_name="insider_fixture",
        )
        print(
            "Insider telemetry collector complete. "
            f"{stats['ingested']} new alerts, {stats['updated']} updated."
        )
        return int(stats["ingested"])
    except Exception as exc:
        conn = get_connection()
        try:
            source_id = _ensure_source(conn, source_name=SOURCE_NAME, source_url="insider://fixtures")
            mark_source_failure(conn, source_id, f"insider collector failed: {exc!r}")
            conn.commit()
        finally:
            conn.close()
        print(f"Insider telemetry collector failed: {exc}")
        return 0
