#!/usr/bin/env python3
"""Run an offline, fixture-only collector pipeline for deterministic demos."""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.chans import collect_chans
from collectors.insider_telemetry import collect_insider_telemetry
from collectors.supply_chain import collect_supply_chain
from collectors.telegram import collect_telegram
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


@contextmanager
def _force_env(**overrides):
    previous = {}
    try:
        for key, value in overrides.items():
            previous[key] = os.environ.get(key)
            os.environ[key] = str(value)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _ensure_initialized():
    init_db()
    migrate_schema()
    seed_default_sources()
    seed_default_keywords()
    seed_default_pois()
    seed_default_protected_locations()
    seed_default_events()
    seed_threat_actors()


def _seed_external_bridge_alert():
    conn = get_connection()
    try:
        rss_source = conn.execute(
            "SELECT id FROM sources WHERE source_type = 'rss' AND name = ? ORDER BY id LIMIT 1",
            ("External OSINT Bridge (Fixture)",),
        ).fetchone()
        if rss_source:
            source_id = int(rss_source["id"])
        else:
            conn.execute(
                """INSERT INTO sources (name, url, source_type, credibility_score, active)
                VALUES (?, ?, 'rss', ?, 1)""",
                ("External OSINT Bridge (Fixture)", "https://example.org/fixture-feed", 0.55),
            )
            source_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

        keyword = conn.execute(
            "SELECT id FROM keywords WHERE term = 'death threat' ORDER BY id LIMIT 1"
        ).fetchone()
        if not keyword:
            conn.commit()
            return 0

        existing = conn.execute(
            "SELECT id FROM alerts WHERE url = ?",
            ("https://example.org/demo-insider-external-bridge",),
        ).fetchone()
        if existing:
            conn.commit()
            return 0

        conn.execute(
            """INSERT INTO alerts
            (source_id, keyword_id, title, content, url, matched_term, published_at,
             risk_score, ors_score, severity, reviewed)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, 0)""",
            (
                source_id,
                int(keyword["id"]),
                "External forum signal references insider-linked identifier and vendor",
                "Synthetic bridge event linking user_id EMP-7415 and vendor_id SC-004.",
                "https://example.org/demo-insider-external-bridge",
                "death threat",
                78.0,
                78.0,
                "high",
            ),
        )
        alert_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'user_id', ?, CURRENT_TIMESTAMP)""",
            (alert_id, "emp-7415"),
        )
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'vendor_id', ?, CURRENT_TIMESTAMP)""",
            (alert_id, "sc-004"),
        )
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, 'domain', ?, CURRENT_TIMESTAMP)""",
            (alert_id, "aster-cloud.example"),
        )
        conn.commit()
        return 1
    finally:
        conn.close()


def _latest_source_status(source_type):
    conn = get_connection()
    try:
        row = conn.execute(
            """SELECT source_type, name, last_status, last_error, fail_streak
            FROM sources
            WHERE source_type = ?
            ORDER BY id DESC
            LIMIT 1""",
            (source_type,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _assert_not_error(source_type):
    row = _latest_source_status(source_type)
    if not row:
        raise RuntimeError(f"missing source registration for {source_type}")
    if row.get("last_status") == "error":
        raise RuntimeError(
            f"{source_type} collector reported error: {row.get('last_error') or 'unknown error'}"
        )
    if row.get("last_status") == "skipped":
        raise RuntimeError(
            f"{source_type} collector was skipped: {row.get('last_error') or 'no reason provided'}"
        )
    return row


def main():
    _ensure_initialized()

    with _force_env(
        PI_ENABLE_TELEGRAM_COLLECTOR="1",
        PI_ENABLE_CHANS_COLLECTOR="1",
        PI_ENABLE_SUPPLY_CHAIN="1",
    ):
        counts = {
            "telegram": int(collect_telegram()),
            "chans": int(collect_chans()),
            "insider": int(collect_insider_telemetry()),
            "supply_chain": int(collect_supply_chain()),
            "external_bridge": int(_seed_external_bridge_alert()),
        }

    statuses = {
        "telegram": _assert_not_error("telegram"),
        "chans": _assert_not_error("chans"),
        "insider": _assert_not_error("insider"),
        "supply_chain": _assert_not_error("supply_chain"),
    }

    print("Fixture-only demo pipeline complete.")
    print(
        "Counts: "
        f"telegram={counts['telegram']} chans={counts['chans']} "
        f"insider={counts['insider']} supply_chain={counts['supply_chain']} "
        f"external_bridge={counts['external_bridge']}"
    )
    print(
        "Statuses: "
        f"telegram={statuses['telegram']['last_status']} "
        f"chans={statuses['chans']['last_status']} "
        f"insider={statuses['insider']['last_status']} "
        f"supply_chain={statuses['supply_chain']['last_status']}"
    )


if __name__ == "__main__":
    main()
