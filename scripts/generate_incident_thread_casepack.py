#!/usr/bin/env python3
"""
Generate an analyst-ready investigation thread case pack.

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

from collectors.chans import collect_chans
from collectors.insider_telemetry import collect_insider_telemetry
from collectors.supply_chain import collect_supply_chain
from collectors.telegram import collect_telegram
from database import init_db as db_init
from database.init_db import get_connection
from processor.correlation import build_incident_threads

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
    with _force_env(
        PI_ENABLE_TELEGRAM_COLLECTOR="1",
        PI_ENABLE_CHANS_COLLECTOR="1",
        PI_ENABLE_SUPPLY_CHAIN="1",
    ):
        telegram_count = collect_telegram()
        chans_count = collect_chans()
        insider_count = collect_insider_telemetry()
        supply_chain_count = collect_supply_chain()
        external_bridge_count = _seed_external_bridge_alert()
    return {
        "telegram": int(telegram_count),
        "chans": int(chans_count),
        "insider": int(insider_count),
        "supply_chain": int(supply_chain_count),
        "external_bridge": int(external_bridge_count),
    }


def _seed_external_bridge_alert():
    """Insert one synthetic external alert to prove insider↔external convergence."""
    conn = get_connection()
    try:
        rss_source = conn.execute(
            """SELECT id FROM sources
            WHERE source_type = 'rss' AND name = ?
            ORDER BY id LIMIT 1""",
            ("External OSINT Bridge (Fixture)",),
        ).fetchone()
        if not rss_source:
            conn.execute(
                """INSERT INTO sources (name, url, source_type, credibility_score, active)
                VALUES (?, ?, 'rss', ?, 1)""",
                ("External OSINT Bridge (Fixture)", "https://example.org/fixture-feed", 0.55),
            )
            source_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        else:
            source_id = int(rss_source["id"])
        keyword = conn.execute(
            "SELECT id FROM keywords WHERE term = 'death threat' ORDER BY id LIMIT 1"
        ).fetchone()
        if not keyword:
            return 0
        existing = conn.execute(
            "SELECT id FROM alerts WHERE url = ?",
            ("https://example.org/demo-insider-external-bridge",),
        ).fetchone()
        if existing:
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
                "Synthetic bridge event for casepack provenance: links user_id EMP-7415 and vendor_id SC-004.",
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


def _choose_thread(threads):
    if not threads:
        return None

    external_types = {"rss", "reddit", "pastebin", "telegram", "chans"}

    def _score(thread):
        source_types = set(thread.get("source_types") or [])
        has_insider = 1 if "insider" in source_types else 0
        has_vendor = 1 if "supply_chain" in source_types else 0
        has_external = 1 if source_types.intersection(external_types) else 0
        has_cross_domain = 1 if (has_insider and (has_external or has_vendor)) else 0
        reason_codes = set(thread.get("reason_codes") or [])
        reason_bonus = 0
        for key in ("shared_user_id", "shared_device_id", "shared_vendor_id", "shared_actor_handle"):
            if key in reason_codes:
                reason_bonus += 1
        return (
            has_cross_domain,
            has_insider,
            has_vendor,
            reason_bonus,
            float(thread.get("thread_confidence") or 0.0),
            float(thread.get("max_ors_score") or 0.0),
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


def _table_lines(headers, rows):
    if not rows:
        return []
    line_header = "| " + " | ".join(headers) + " |"
    line_sep = "|" + "|".join("---" for _ in headers) + "|"
    lines = [line_header, line_sep]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def _build_thread_context(thread):
    alert_ids = [int(item["alert_id"]) for item in thread.get("timeline", []) if item.get("alert_id")]
    if not alert_ids:
        return {
            "user_ids": set(),
            "device_ids": set(),
            "vendor_ids": set(),
            "domains": set(),
            "insider_rows": [],
            "vendor_rows": [],
        }

    conn = get_connection()
    try:
        placeholders = ",".join("?" for _ in alert_ids)
        entity_rows = conn.execute(
            f"""SELECT entity_type, entity_value
            FROM alert_entities
            WHERE alert_id IN ({placeholders})""",
            alert_ids,
        ).fetchall()
        user_ids = {
            str(row["entity_value"]).strip().lower()
            for row in entity_rows
            if row["entity_type"] == "user_id" and row["entity_value"]
        }
        device_ids = {
            str(row["entity_value"]).strip().lower()
            for row in entity_rows
            if row["entity_type"] == "device_id" and row["entity_value"]
        }
        vendor_ids = {
            str(row["entity_value"]).strip().lower()
            for row in entity_rows
            if row["entity_type"] == "vendor_id" and row["entity_value"]
        }
        domains = {
            str(row["entity_value"]).strip().lower()
            for row in entity_rows
            if row["entity_type"] == "domain" and row["entity_value"]
        }

        insider_rows = []
        if user_ids:
            user_placeholders = ",".join("?" for _ in user_ids)
            insider_rows = conn.execute(
                f"""SELECT subject_id, subject_name, irs_score, risk_tier, reason_codes_json
                FROM insider_risk_assessments
                WHERE lower(subject_id) IN ({user_placeholders})
                ORDER BY irs_score DESC""",
                list(sorted(user_ids)),
            ).fetchall()

        vendor_rows = []
        vendor_match_terms = list(sorted(vendor_ids))
        if domains:
            vendor_match_terms.extend(sorted(domains))
        if vendor_match_terms:
            vendor_placeholders = ",".join("?" for _ in vendor_match_terms)
            vendor_rows = conn.execute(
                f"""SELECT profile_id, vendor_name, vendor_domain, vendor_risk_score, risk_tier, reason_codes_json
                FROM supply_chain_risk_assessments
                WHERE lower(profile_id) IN ({vendor_placeholders})
                   OR lower(vendor_domain) IN ({vendor_placeholders})
                ORDER BY vendor_risk_score DESC""",
                vendor_match_terms + vendor_match_terms,
            ).fetchall()

        return {
            "user_ids": user_ids,
            "device_ids": device_ids,
            "vendor_ids": vendor_ids,
            "domains": domains,
            "insider_rows": insider_rows,
            "vendor_rows": vendor_rows,
        }
    finally:
        conn.close()


def _render_no_thread_casepack(counts):
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Investigation Thread Case Pack",
        "",
        f"Generated: {generated_at}",
        "",
        "## Fixture Ingestion Summary",
        f"- Telegram prototype alerts ingested: **{counts['telegram']}**",
        f"- Chans prototype alerts ingested: **{counts['chans']}**",
        f"- Insider telemetry alerts ingested: **{counts['insider']}**",
        f"- Supply-chain alerts ingested: **{counts['supply_chain']}**",
        f"- External bridge alerts ingested: **{counts['external_bridge']}**",
        "",
        "## Result",
        "No correlated SOI thread met the current clustering thresholds in this isolated run.",
        "",
        "## Reproduce",
        "```bash",
        "make init",
        "PI_ENABLE_TELEGRAM_COLLECTOR=1 PI_ENABLE_CHANS_COLLECTOR=1 PI_ENABLE_SUPPLY_CHAIN=1 python run.py scrape",
        "python scripts/generate_incident_thread_casepack.py",
        "```",
        "",
    ]
    return "\n".join(lines)


def _render_casepack(thread, counts):
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    max_ors = float(thread.get("max_ors_score") or 0.0)
    max_tas = float(thread.get("max_tas_score") or 0.0)
    thread_conf = float(thread.get("thread_confidence") or 0.0)
    tier = _escalation_tier(max_ors)
    context = _build_thread_context(thread)

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

    recommendation = {
        "CRITICAL": "Immediate escalation to protective detail lead and intelligence manager (target: 30 minutes).",
        "ELEVATED": "Escalate to analyst lead for enhanced monitoring and immediate review (target: 4 hours).",
        "ROUTINE": "Maintain monitoring queue and reassess at next collection cycle.",
        "LOW": "Track passively and suppress unless additional corroboration appears.",
    }[tier]

    lines = [
        "# Investigation Thread Case Pack",
        "",
        f"Generated: {generated_at}",
        "",
        "## Scope and Sanitization",
        "- Synthetic fixture data only (no production identities, no classified/regulated datasets).",
        "- Purpose: demonstrate cross-domain correlation and explainable prioritization.",
        "",
        "## Fixture Ingestion Summary",
        f"- Telegram prototype alerts ingested: **{counts['telegram']}**",
        f"- Chans prototype alerts ingested: **{counts['chans']}**",
        f"- Insider telemetry alerts ingested: **{counts['insider']}**",
        f"- Supply-chain alerts ingested: **{counts['supply_chain']}**",
        f"- External bridge alerts ingested: **{counts['external_bridge']}**",
        "",
        "## Thread Snapshot",
        f"- `thread_id`: `{thread.get('thread_id')}`",
        f"- `label`: **{thread.get('label')}**",
        f"- alerts: **{thread.get('alerts_count')}**",
        f"- sources: **{thread.get('sources_count')}** ({', '.join(thread.get('sources') or [])})",
        f"- source types: **{', '.join(thread.get('source_types') or [])}**",
        f"- time window: **{thread.get('start_ts')} → {thread.get('end_ts')}**",
        f"- max ORS: **{max_ors:.1f}**",
        f"- max TAS: **{max_tas:.1f}**",
        f"- thread confidence: **{thread_conf:.2f}**",
        f"- recommended escalation tier: **{tier}**",
        "",
        "## Correlation Evidence",
        f"- reason codes: {', '.join(thread.get('reason_codes') or []) or 'none'}",
        f"- shared entities: {', '.join(thread.get('shared_entities') or []) or 'none'}",
        f"- matched terms: {', '.join(thread.get('matched_terms') or []) or 'none'}",
        "",
        "## Provenance Keys",
        f"- user_id values in thread: {', '.join(sorted(context['user_ids'])) or 'none'}",
        f"- device_id values in thread: {', '.join(sorted(context['device_ids'])) or 'none'}",
        f"- vendor_id values in thread: {', '.join(sorted(context['vendor_ids'])) or 'none'}",
        f"- domain values in thread: {', '.join(sorted(context['domains'])) or 'none'}",
        "",
    ]

    insider_table_rows = []
    for row in context["insider_rows"]:
        insider_table_rows.append(
            [
                str(row["subject_id"] or ""),
                str(row["subject_name"] or ""),
                f"{float(row['irs_score'] or 0.0):.1f}",
                str(row["risk_tier"] or ""),
            ]
        )
    lines.extend(["## Insider Risk Context"])
    if insider_table_rows:
        lines.extend(_table_lines(["Subject ID", "Subject Name", "IRS", "Tier"], insider_table_rows))
    else:
        lines.append("No insider assessment rows matched thread provenance keys.")
    lines.append("")

    vendor_table_rows = []
    for row in context["vendor_rows"]:
        vendor_table_rows.append(
            [
                str(row["profile_id"] or ""),
                str(row["vendor_name"] or ""),
                str(row["vendor_domain"] or ""),
                f"{float(row['vendor_risk_score'] or 0.0):.1f}",
                str(row["risk_tier"] or ""),
            ]
        )
    lines.extend(["## Supply-Chain Context"])
    if vendor_table_rows:
        lines.extend(
            _table_lines(
                ["Vendor ID", "Vendor Name", "Domain", "Risk Score", "Tier"],
                vendor_table_rows,
            )
        )
    else:
        lines.append("No vendor assessment rows matched thread provenance keys.")
    lines.append("")

    lines.extend(
        [
            "## Timeline",
            "| Timestamp | Source | Type | ORS | TAS | Matched Term | Title |",
            "|---|---|---|---:|---:|---|---|",
        ]
    )
    lines.extend(timeline_rows)

    pair_rows = []
    for item in thread.get("pair_evidence", [])[:10]:
        pair_rows.append(
            [
                str(item.get("left_alert_id")),
                str(item.get("right_alert_id")),
                f"{float(item.get('score') or 0.0):.2f}",
                ", ".join(item.get("reason_codes") or []) or "none",
            ]
        )
    lines.append("")
    lines.append("## Pairwise Link Provenance")
    if pair_rows:
        lines.extend(_table_lines(["Left Alert", "Right Alert", "Score", "Reason Codes"], pair_rows))
    else:
        lines.append("No pair evidence rows captured.")

    lines.extend(
        [
            "",
            "## Analyst Action",
            recommendation,
            "",
            "## Reproduce",
            "```bash",
            "make init",
            "PI_ENABLE_TELEGRAM_COLLECTOR=1 PI_ENABLE_CHANS_COLLECTOR=1 PI_ENABLE_SUPPLY_CHAIN=1 python run.py scrape",
            "python scripts/generate_incident_thread_casepack.py",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def main():
    with _isolated_db():
        _ensure_initialized()
        counts = _collect_fixture_sources()
        threads = build_incident_threads(
            days=30,
            window_hours=72,
            min_cluster_size=2,
            include_demo=False,
        )
        selected = _choose_thread(threads)

        DOCS_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        if selected is None:
            DOCS_OUTPUT.write_text(_render_no_thread_casepack(counts), encoding="utf-8")
            print(f"Incident thread case pack written: {DOCS_OUTPUT}")
            print("  No correlated thread found in isolated run.")
            return

        DOCS_OUTPUT.write_text(_render_casepack(selected, counts), encoding="utf-8")
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
