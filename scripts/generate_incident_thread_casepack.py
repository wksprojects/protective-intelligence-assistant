#!/usr/bin/env python3
"""
Generate an analyst-ready incident thread case pack.

Output:
    docs/incident_thread_casepack.md
"""

from __future__ import annotations

import os
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from analytics.soi_threads import build_soi_threads
from database import init_db as db_init
from scraper.chans_collector import run_chans_collector
from scraper.telegram_collector import run_telegram_collector

DOCS_OUTPUT = Path("docs/incident_thread_casepack.md")


@contextmanager
def _force_env(**overrides):
    old = {}
    try:
        for key, value in overrides.items():
            old[key] = os.environ.get(key)
            os.environ[key] = str(value)
        yield
    finally:
        for key, previous in old.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous


@contextmanager
def _isolated_db():
    old_db_path = db_init.DB_PATH
    fd, temp_db_path = tempfile.mkstemp(prefix="pi_casepack_", suffix=".db")
    os.close(fd)
    try:
        db_init.DB_PATH = temp_db_path
        yield
    finally:
        db_init.DB_PATH = old_db_path
        try:
            os.remove(temp_db_path)
        except OSError:
            pass


def _ensure_initialized():
    db_init.init_db()
    db_init.migrate_schema()
    db_init.seed_default_sources()
    db_init.seed_default_keywords()
    db_init.seed_default_pois()
    db_init.seed_default_protected_locations()
    db_init.seed_default_events()
    db_init.seed_threat_actors()


def _collect_fixture_sources():
    with _force_env(PI_ENABLE_TELEGRAM_COLLECTOR="1", PI_ENABLE_CHANS_COLLECTOR="1"):
        telegram_count = run_telegram_collector()
        chans_count = run_chans_collector()
    return int(telegram_count), int(chans_count)


def _choose_thread(threads):
    if not threads:
        return None

    def _score(thread):
        source_types = {
            item.get("source_type")
            for item in thread.get("timeline", [])
            if item.get("source_type")
        }
        has_cross = 1 if {"telegram", "chans"}.issubset(source_types) else 0
        return (
            has_cross,
            float(thread.get("max_ors_score") or 0.0),
            float(thread.get("max_tas_score") or 0.0),
            int(thread.get("alerts_count") or 0),
        )

    return sorted(threads, key=_score, reverse=True)[0]


def _escalation_tier(score):
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "ELEVATED"
    if score >= 40:
        return "ROUTINE"
    return "LOW"


def _render_no_thread_casepack(telegram_count, chans_count):
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Incident Thread Case Pack",
        "",
        f"Generated: {generated_at}",
        "",
        "## Ingestion Summary",
        f"- Telegram prototype alerts ingested this run: **{telegram_count}**",
        f"- Chans prototype alerts ingested this run: **{chans_count}**",
        "",
        "## Result",
        "No correlated SOI thread met the current clustering thresholds in this isolated run.",
        "",
        "## Reproduce",
        "```bash",
        "make init",
        "PI_ENABLE_TELEGRAM_COLLECTOR=1 PI_ENABLE_CHANS_COLLECTOR=1 python run.py scrape",
        'curl "http://localhost:8000/analytics/soi-threads?days=14&window_hours=72&min_cluster_size=2"',
        "```",
        "",
    ]
    return "\n".join(lines)


def _render_casepack(thread, telegram_count, chans_count):
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    max_ors = float(thread.get("max_ors_score") or 0.0)
    max_tas = float(thread.get("max_tas_score") or 0.0)
    tier = _escalation_tier(max_ors)

    timeline_rows = []
    for item in thread.get("timeline", []):
        timeline_rows.append(
            "| {ts} | {src} | {stype} | {ors:.1f} | {tas:.1f} | {term} | {title} |".format(
                ts=item.get("timestamp") or "",
                src=item.get("source_name") or "unknown",
                stype=item.get("source_type") or "unknown",
                ors=float(item.get("ors_score") or 0.0),
                tas=float(item.get("tas_score") or 0.0),
                term=item.get("matched_term") or "",
                title=(item.get("title") or "").replace("|", "/"),
            )
        )

    actor_handles = ", ".join(thread.get("actor_handles") or []) or "none"
    shared_entities = ", ".join(thread.get("shared_entities") or []) or "none"
    matched_terms = ", ".join(thread.get("matched_terms") or []) or "none"
    poi_names = ", ".join(thread.get("poi_names") or []) or "none"

    evidence_notes = []
    if thread.get("actor_handles"):
        evidence_notes.append("Actor-handle evidence present; validate continuity during analyst review.")
    if thread.get("shared_entities"):
        evidence_notes.append("Shared entities observed across alerts.")
    if len(thread.get("sources", [])) >= 2:
        evidence_notes.append("Multi-source corroboration across independent feeds.")
    if thread.get("matched_terms"):
        evidence_notes.append("Recurring threat vocabulary over a constrained time window.")
    if not evidence_notes:
        evidence_notes.append("Temporal + term-level linkage met thread clustering threshold.")

    recommendation = {
        "CRITICAL": "Immediate escalation to protective detail lead and intelligence manager (target: 30 minutes).",
        "ELEVATED": "Escalate to analyst lead for enhanced monitoring and immediate review (target: 4 hours).",
        "ROUTINE": "Maintain monitoring queue and reassess at next collection cycle.",
        "LOW": "Track passively and suppress unless additional corroboration appears.",
    }[tier]

    lines = [
        "# Incident Thread Case Pack",
        "",
        f"Generated: {generated_at}",
        "",
        "## Ingestion Summary",
        f"- Telegram prototype alerts ingested this run: **{telegram_count}**",
        f"- Chans prototype alerts ingested this run: **{chans_count}**",
        "",
        "## Thread Snapshot",
        f"- `thread_id`: `{thread.get('thread_id')}`",
        f"- `label`: **{thread.get('label')}**",
        f"- alerts: **{thread.get('alerts_count')}**",
        f"- sources: **{thread.get('sources_count')}** ({', '.join(thread.get('sources') or [])})",
        f"- time window: **{thread.get('start_ts')} → {thread.get('end_ts')}**",
        f"- max ORS: **{max_ors:.1f}**",
        f"- max TAS: **{max_tas:.1f}**",
        f"- recommended escalation tier: **{tier}**",
        "",
        "## Correlation Evidence",
        f"- actor handles: {actor_handles}",
        f"- shared entities: {shared_entities}",
        f"- matched terms: {matched_terms}",
        f"- linked POIs: {poi_names}",
        "",
    ]
    lines.extend(f"- {note}" for note in evidence_notes)
    lines.extend(
        [
            "",
            "## Timeline",
            "| Timestamp | Source | Type | ORS | TAS | Matched Term | Title |",
            "|---|---|---|---:|---:|---|---|",
        ]
    )
    lines.extend(timeline_rows)
    lines.extend(
        [
            "",
            "## Analyst Action",
            recommendation,
            "",
            "## Reproduce",
            "```bash",
            "make init",
            "PI_ENABLE_TELEGRAM_COLLECTOR=1 PI_ENABLE_CHANS_COLLECTOR=1 python run.py scrape",
            'curl "http://localhost:8000/analytics/soi-threads?days=14&window_hours=72&min_cluster_size=2"',
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def main():
    with _isolated_db():
        _ensure_initialized()
        telegram_count, chans_count = _collect_fixture_sources()
        threads = build_soi_threads(days=30, window_hours=72, min_cluster_size=2, include_demo=False)
        selected = _choose_thread(threads)

    DOCS_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if selected is None:
        DOCS_OUTPUT.write_text(
            _render_no_thread_casepack(telegram_count=telegram_count, chans_count=chans_count),
            encoding="utf-8",
        )
        print(f"Incident thread case pack written: {DOCS_OUTPUT}")
        print("  No correlated thread found in isolated run.")
        return

    DOCS_OUTPUT.write_text(
        _render_casepack(selected, telegram_count=telegram_count, chans_count=chans_count),
        encoding="utf-8",
    )
    print(f"Incident thread case pack written: {DOCS_OUTPUT}")
    print(
        "  Thread: {thread_id} | alerts={alerts} | sources={sources}".format(
            thread_id=selected.get("thread_id"),
            alerts=selected.get("alerts_count"),
            sources=selected.get("sources_count"),
        )
    )


if __name__ == "__main__":
    main()
