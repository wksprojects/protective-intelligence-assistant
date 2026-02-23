"""Optional ACLED collector.

Runs only when ACLED credentials are present in environment.
If not configured, it no-ops safely.
"""

import os

import requests

from analytics.dedup import check_duplicate
from analytics.entity_extraction import extract_and_store_alert_entities
from analytics.ep_pipeline import process_ep_signals
from analytics.risk_scoring import increment_keyword_frequency, score_alert
from database.init_db import get_connection
from scraper.rss_scraper import alert_exists, get_active_keywords
from scraper.source_health import mark_source_failure, mark_source_skipped, mark_source_success

ACLED_API = "https://api.acleddata.com/acled/read"


def _configured():
    return bool(os.getenv("ACLED_API_KEY") and os.getenv("ACLED_EMAIL"))


def run_acled_collector(frequency_snapshot=None):
    if not _configured():
        print("ACLED collector skipped (ACLED_API_KEY/ACLED_EMAIL not configured).")
        conn = get_connection()
        try:
            source = conn.execute(
                "SELECT id FROM sources WHERE url = ?",
                ("https://acleddata.com",),
            ).fetchone()
            if source:
                mark_source_skipped(conn, source["id"], "ACLED credentials not configured")
                conn.commit()
        finally:
            conn.close()
        return 0

    conn = get_connection()
    source_id = None
    try:
        keywords = get_active_keywords(conn)
        source = conn.execute(
            "SELECT id FROM sources WHERE url = ?",
            ("https://acleddata.com",),
        ).fetchone()
        if source:
            source_id = source["id"]
        else:
            conn.execute(
                "INSERT INTO sources (name, url, source_type, credibility_score) VALUES (?, ?, ?, ?)",
                ("ACLED Events", "https://acleddata.com", "acled", 0.8),
            )
            source_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        preferred_keyword = next((k for k in keywords if k.get("term", "").lower() == "protest"), None)
        if preferred_keyword is None and keywords:
            preferred_keyword = keywords[0]
        if preferred_keyword is None:
            print("ACLED collector skipped (no active keywords).")
            return 0

        params = {
            "key": os.getenv("ACLED_API_KEY"),
            "email": os.getenv("ACLED_EMAIL"),
            "limit": 25,
        }
        response = requests.get(ACLED_API, params=params, timeout=15)
        response.raise_for_status()
        payload = response.json() or {}
        rows = payload.get("data") or []

        created = 0
        for row in rows:
            title = f"ACLED {row.get('event_type', 'event')} - {row.get('admin1', row.get('country', 'unknown'))}"
            content = (
                f"Actor1: {row.get('actor1', '')}; Actor2: {row.get('actor2', '')}; "
                f"Notes: {row.get('notes', '')}; Fatalities: {row.get('fatalities', '')}"
            )
            url = row.get("source", "https://acleddata.com")
            if alert_exists(conn, source_id, preferred_keyword["id"], url):
                continue

            content_hash, duplicate_of = check_duplicate(conn, title, content)
            conn.execute(
                """INSERT INTO alerts
                (source_id, keyword_id, title, content, url, matched_term,
                 content_hash, duplicate_of, published_at, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_id,
                    preferred_keyword["id"],
                    title,
                    content[:2000],
                    url,
                    preferred_keyword["term"],
                    content_hash,
                    duplicate_of,
                    row.get("event_date"),
                    "low",
                ),
            )
            alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            if duplicate_of is not None:
                continue

            score_args = frequency_snapshot.get(preferred_keyword["id"]) if frequency_snapshot else None
            baseline = score_alert(
                conn,
                alert_id,
                preferred_keyword["id"],
                source_id,
                published_at=row.get("event_date"),
                frequency_override=score_args[0] if score_args else None,
                z_score_override=score_args[1] if score_args else None,
            )
            extract_and_store_alert_entities(conn, alert_id, f"{title}\n{content}")
            process_ep_signals(
                conn,
                alert_id=alert_id,
                title=title,
                content=content,
                keyword_category=preferred_keyword.get("category"),
                baseline_score=baseline,
            )
            increment_keyword_frequency(conn, preferred_keyword["id"])
            created += 1

        conn.commit()
        mark_source_success(conn, source_id)
        conn.commit()
        print(f"ACLED collector complete. {created} new alerts.")
        return created
    except Exception as exc:
        if source_id is not None:
            mark_source_failure(conn, source_id, f"ACLED collector error: {exc!r}")
            conn.commit()
        print(f"ACLED collector failed: {exc}")
        return 0
    finally:
        conn.close()
