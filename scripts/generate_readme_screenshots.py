"""Generate README screenshot artifacts for insider/supply-chain/convergence/queue outputs."""

from __future__ import annotations

import json
import sys
import textwrap
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from analytics.insider_risk import list_insider_risk
from analytics.supply_chain_risk import list_supply_chain_risk
from analytics.utils import utcnow
from collectors.insider_telemetry import ingest_insider_events
from collectors.supply_chain import ingest_supply_chain_profiles
from database import init_db as db_init
from database.init_db import (
    get_connection,
    init_db,
    migrate_schema,
    seed_default_events,
    seed_default_keywords,
    seed_default_pois,
    seed_default_protected_locations,
    seed_default_sources,
    seed_threat_actors,
)
from processor.correlation import build_incident_threads

OUT_DIR = REPO_ROOT / "docs" / "screenshots"
INSIDER_IMG = OUT_DIR / "insider_risk_endpoint.png"
SUPPLY_IMG = OUT_DIR / "supply_chain_risk_endpoint.png"
THREAD_IMG = OUT_DIR / "cross_domain_convergence.png"
QUEUE_IMG = OUT_DIR / "investigation_queues_panel.png"


def _load_font(size):
    candidates = [
        "/System/Library/Fonts/Supplemental/Menlo.ttc",
        "/System/Library/Fonts/SFNSMono.ttf",
        "/Library/Fonts/Courier New.ttf",
    ]
    for candidate in candidates:
        font_path = Path(candidate)
        if font_path.exists():
            return ImageFont.truetype(str(font_path), size=size)
    return ImageFont.load_default()


def _seed_temp_db(db_path):
    db_init.DB_PATH = str(db_path)
    init_db()
    migrate_schema()
    seed_default_sources()
    seed_default_keywords()
    seed_default_pois()
    seed_default_protected_locations()
    seed_default_events()
    seed_threat_actors()


def _insert_external_user_signal(user_id):
    conn = get_connection()
    try:
        rss_source_id = conn.execute(
            "SELECT id FROM sources WHERE source_type = 'rss' ORDER BY id LIMIT 1"
        ).fetchone()["id"]
        keyword_id = conn.execute(
            "SELECT id FROM keywords WHERE term = 'death threat'"
        ).fetchone()["id"]
        published_at = (utcnow() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            """INSERT INTO alerts
            (source_id, keyword_id, title, content, url, matched_term, severity, published_at, risk_score, ors_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rss_source_id,
                keyword_id,
                "External corroboration linked to insider user ID",
                "Cross-domain reference with matching user identifier.",
                "https://example.com/insider-convergence-signal",
                "death threat",
                "medium",
                published_at,
                71.0,
                71.0,
            ),
        )
        alert_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'user_id', ?, CURRENT_TIMESTAMP)""",
            (alert_id, user_id),
        )
        conn.commit()
    finally:
        conn.close()


def _build_payloads():
    ingest_insider_events(
        [
            {
                "event_id": "edr-evt-001",
                "subject_id": "EMP-9901",
                "subject_name": "Casey Rivers",
                "timestamp": "2026-02-27 03:14:00",
                "title": "Bulk engineering archive transfer",
                "summary": "Large transfer after midnight from privileged endpoint.",
                "signals": {
                    "access_pattern_deviation": 0.86,
                    "off_hours_activity": 0.92,
                    "resource_sensitivity_access": 0.88,
                    "data_volume_anomaly": 0.83,
                    "bulk_data_download_gb": 48.0,
                    "usb_write_gb": 14.0,
                    "cloud_upload_gb": 39.0,
                    "physical_logical_mismatch": 0.75,
                    "badge_login_mismatch": 0.9,
                    "access_escalation": 0.73,
                    "communication_metadata_shift": 0.67,
                    "hr_context_risk": 0.61,
                    "temporal_anomaly": 0.88,
                    "cumulative_risk_acceleration": 0.84,
                },
                "resignation_pending": True,
                "related_entities": [
                    {"entity_type": "user_id", "entity_value": "emp-9901"},
                    {"entity_type": "device_id", "entity_value": "lpt-77"},
                    {"entity_type": "vendor_id", "entity_value": "ven-8472"},
                    {"entity_type": "domain", "entity_value": "drop-sync.example"},
                ],
            }
        ],
        source_name="Insider Telemetry (Synthetic EDR Feed)",
        source_url="insider://edr-fixture-adapter",
        observer_name="insider_screenshot_seed",
    )

    ingest_supply_chain_profiles(
        [
            {
                "external_id": "ven-8472",
                "name": "HarborLine Logistics",
                "domain": "harborline.example",
                "country": "IR",
                "factors": {
                    "single_point_of_failure_concentration": 0.88,
                    "access_privilege_scope": 0.74,
                    "data_sensitivity_exposure": 0.69,
                    "compliance_posture_indicators": 0.32,
                },
                "recent_incidents": 2,
            }
        ],
        source_name="Supply Chain Risk (Synthetic TPRM Feed)",
        source_url="supply-chain://tprm-fixture-adapter",
        observer_name="supply_chain_screenshot_seed",
    )

    _insert_external_user_signal("emp-9901")

    insider_rows = list_insider_risk(limit=20)
    insider_row = next((row for row in insider_rows if row.get("subject_id") == "EMP-9901"), insider_rows[0])
    supply_rows = list_supply_chain_risk(limit=20)
    supply_row = next((row for row in supply_rows if row.get("profile_id") == "ven-8472"), supply_rows[0])
    threads = build_incident_threads(days=30, window_hours=168, min_cluster_size=2, limit=20)

    ranked = []
    for thread in threads:
        reasons = set(thread.get("reason_codes") or [])
        source_types = set(thread.get("source_types") or [])
        score = 0
        if "shared_user_id" in reasons:
            score += 2
        if "shared_vendor_id" in reasons:
            score += 2
        if {"insider", "supply_chain", "rss"}.issubset(source_types):
            score += 2
        ranked.append((score, thread))
    ranked.sort(key=lambda item: item[0], reverse=True)
    thread_row = ranked[0][1] if ranked else {}

    insider_payload = {
        "endpoint": "GET /analytics/insider-risk",
        "subject_id": insider_row.get("subject_id"),
        "irs_score": insider_row.get("irs_score"),
        "risk_tier": insider_row.get("risk_tier"),
        "reason_codes": insider_row.get("reason_codes"),
        "taxonomy_hits": insider_row.get("taxonomy_hits"),
        "signal_breakdown": insider_row.get("signal_breakdown"),
    }
    supply_payload = {
        "endpoint": "GET /analytics/supply-chain-risk",
        "profile_id": supply_row.get("profile_id"),
        "vendor_name": supply_row.get("vendor_name"),
        "vendor_risk_score": supply_row.get("vendor_risk_score"),
        "risk_tier": supply_row.get("risk_tier"),
        "reason_codes": supply_row.get("reason_codes"),
        "factor_breakdown": supply_row.get("factor_breakdown"),
    }
    convergence_payload = {
        "endpoint": "GET /analytics/soi-threads",
        "thread_id": thread_row.get("thread_id"),
        "source_types": thread_row.get("source_types"),
        "reason_codes": thread_row.get("reason_codes"),
        "shared_entities": [
            value
            for value in (thread_row.get("shared_entities") or [])
            if value.startswith(("user_id:", "vendor_id:", "device_id:"))
        ],
        "pair_evidence": (thread_row.get("pair_evidence") or [])[:2],
    }
    queue_payload = {
        "snapshot": "Investigation Queues payload",
        "insider_queue": [
            {
                "subject_id": row.get("subject_id"),
                "irs_score": row.get("irs_score"),
                "risk_tier": row.get("risk_tier"),
                "reason_codes": (row.get("reason_codes") or [])[:3],
            }
            for row in insider_rows[:3]
        ],
        "third_party_queue": [
            {
                "profile_id": row.get("profile_id"),
                "vendor_name": row.get("vendor_name"),
                "vendor_risk_score": row.get("vendor_risk_score"),
                "risk_tier": row.get("risk_tier"),
                "reason_codes": (row.get("reason_codes") or [])[:3],
            }
            for row in supply_rows[:3]
        ],
        "investigation_threads": [
            {
                "thread_id": row.get("thread_id"),
                "source_types": row.get("source_types"),
                "alerts_count": row.get("alerts_count"),
                "thread_confidence": row.get("thread_confidence"),
                "reason_codes": (row.get("reason_codes") or [])[:4],
            }
            for row in threads[:3]
        ],
    }
    return insider_payload, supply_payload, convergence_payload, queue_payload


def _render_json_snapshot(path, title, subtitle, payload):
    path.parent.mkdir(parents=True, exist_ok=True)

    title_font = _load_font(42)
    subtitle_font = _load_font(24)
    body_font = _load_font(20)

    payload_json = json.dumps(payload, indent=2, sort_keys=False)
    wrapped_lines = []
    for line in payload_json.splitlines():
        wrapped = textwrap.wrap(line, width=98, replace_whitespace=False) or [line]
        wrapped_lines.extend(wrapped)

    line_height = 30
    body_height = max(540, (len(wrapped_lines) + 2) * line_height)
    width = 1600
    height = 250 + body_height

    image = Image.new("RGB", (width, height), "#0A1020")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((40, 40, width - 40, height - 40), radius=24, fill="#111A2E", outline="#3B4E70", width=3)
    draw.text((80, 78), title, fill="#F3F6FF", font=title_font)
    draw.text((80, 138), subtitle, fill="#AFC2E7", font=subtitle_font)
    draw.multiline_text(
        (80, 195),
        "\n".join(wrapped_lines),
        fill="#DDE8FF",
        font=body_font,
        spacing=8,
    )

    image.save(path)


def main():
    original_db_path = db_init.DB_PATH
    try:
        with TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "screenshot_seed.db"
            _seed_temp_db(db_path)
            insider_payload, supply_payload, convergence_payload, queue_payload = _build_payloads()

        _render_json_snapshot(
            INSIDER_IMG,
            "Insider Risk Queue",
            "Fixture + API ingest path with explainable reason codes.",
            insider_payload,
        )
        _render_json_snapshot(
            SUPPLY_IMG,
            "Supply-Chain Risk Queue",
            "Vendor scoring scaffold with weighted factor breakdown.",
            supply_payload,
        )
        _render_json_snapshot(
            THREAD_IMG,
            "Cross-Domain Convergence",
            "Thread evidence linking insider, external, and vendor signals.",
            convergence_payload,
        )
        _render_json_snapshot(
            QUEUE_IMG,
            "Investigation Queues Payload Snapshot",
            "Insider, third-party, and investigation thread queue data.",
            queue_payload,
        )
    finally:
        db_init.DB_PATH = original_db_path

    print("Generated screenshot artifacts:")
    print(f"  - {INSIDER_IMG}")
    print(f"  - {SUPPLY_IMG}")
    print(f"  - {THREAD_IMG}")
    print(f"  - {QUEUE_IMG}")


if __name__ == "__main__":
    main()
