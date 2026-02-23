"""Prototype chans/fringe-board collector (fixture-first, policy-gated)."""

import json
import os
from pathlib import Path

from analytics.dedup import check_duplicate
from analytics.entity_extraction import extract_and_store_alert_entities
from analytics.ep_pipeline import process_ep_signals
from analytics.risk_scoring import build_frequency_snapshot, increment_keyword_frequency, score_alert
from analytics.utils import utcnow
from database.init_db import get_connection
from scraper.rss_scraper import get_active_keywords, match_keywords
from scraper.source_health import mark_source_failure, mark_source_skipped, mark_source_success

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "chans_fixtures.json"


def _enabled():
    return os.getenv("PI_ENABLE_CHANS_COLLECTOR", "0").strip().lower() in {"1", "true", "yes"}


def _load_fixtures():
    if not FIXTURE_PATH.exists():
        return []
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _ensure_source(conn):
    row = conn.execute(
        "SELECT id FROM sources WHERE source_type = 'chans' AND name = ?",
        ("Chans / Fringe Boards (Prototype)",),
    ).fetchone()
    if row:
        return int(row["id"])
    conn.execute(
        """INSERT INTO sources (name, url, source_type, credibility_score, active)
        VALUES (?, ?, ?, ?, 1)""",
        ("Chans / Fringe Boards (Prototype)", "https://boards.4chan.org", "chans", 0.2),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def _resolve_keyword_id(conn, keyword_cache, post, combined_text):
    matched_term = str(post.get("matched_term", "")).strip()
    category = str(post.get("category", "protective_intel")).strip() or "protective_intel"
    weight = float(post.get("keyword_weight", 3.2) or 3.2)

    if matched_term:
        existing = keyword_cache.get(matched_term.lower())
        if existing:
            return existing["id"], existing["term"], existing.get("category")

    candidate_hits = match_keywords(combined_text, list(keyword_cache.values()))
    if candidate_hits:
        top = candidate_hits[0]
        return top["id"], top["term"], top.get("category")

    if not matched_term:
        matched_term = "chans threat signal"
    conn.execute(
        "INSERT INTO keywords (term, category, weight, active) VALUES (?, ?, ?, 1)",
        (matched_term, category, max(0.1, min(5.0, weight))),
    )
    keyword_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    keyword_cache[matched_term.lower()] = {
        "id": keyword_id,
        "term": matched_term,
        "category": category,
    }
    return keyword_id, matched_term, category


def run_chans_collector(frequency_snapshot=None):
    conn = get_connection()
    source_id = None
    try:
        source_id = _ensure_source(conn)
        if not _enabled():
            mark_source_skipped(conn, source_id, "PI_ENABLE_CHANS_COLLECTOR not set")
            conn.commit()
            print("Chans collector skipped (PI_ENABLE_CHANS_COLLECTOR not set).")
            return 0

        posts = _load_fixtures()
        if not posts:
            mark_source_failure(conn, source_id, "chans fixtures missing or empty")
            conn.commit()
            print("Chans collector skipped (no fixtures found).")
            return 0

        active_keywords = get_active_keywords(conn)
        keyword_cache = {row["term"].strip().lower(): row for row in active_keywords if row.get("term")}
        if frequency_snapshot is None:
            frequency_snapshot = build_frequency_snapshot(
                conn,
                keyword_ids=[row["id"] for row in active_keywords],
            )

        created = 0
        duplicates = 0
        for post in posts:
            title = str(post.get("title", "")).strip()
            content = str(post.get("content", "")).strip()
            url = str(post.get("url", "")).strip()
            if not title or not url:
                continue
            if conn.execute("SELECT id FROM alerts WHERE url = ?", (url,)).fetchone():
                duplicates += 1
                continue

            combined_text = f"{title}\n{content}"
            keyword_id, matched_term, keyword_category = _resolve_keyword_id(
                conn, keyword_cache, post, combined_text
            )

            content_hash, duplicate_of = check_duplicate(conn, title, content)
            conn.execute(
                """INSERT INTO alerts
                (source_id, keyword_id, title, content, url, matched_term,
                 content_hash, duplicate_of, published_at, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_id,
                    keyword_id,
                    title,
                    content[:2000],
                    url,
                    matched_term,
                    content_hash,
                    duplicate_of,
                    post.get("published_at") or utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "low",
                ),
            )
            alert_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
            if duplicate_of is not None:
                duplicates += 1
                continue

            score_args = frequency_snapshot.get(keyword_id)
            baseline_score = score_alert(
                conn,
                alert_id,
                keyword_id,
                source_id,
                published_at=post.get("published_at"),
                frequency_override=score_args[0] if score_args else None,
                z_score_override=score_args[1] if score_args else None,
            )
            extract_and_store_alert_entities(conn, alert_id, combined_text)

            author_handle = str(post.get("author_handle", "")).strip().lower()
            if author_handle:
                conn.execute(
                    """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
                    VALUES (?, 'actor_handle', ?, CURRENT_TIMESTAMP)""",
                    (alert_id, author_handle),
                )

            process_ep_signals(
                conn,
                alert_id=alert_id,
                title=title,
                content=content,
                keyword_category=keyword_category,
                baseline_score=baseline_score,
            )
            increment_keyword_frequency(conn, keyword_id)
            created += 1

        mark_source_success(conn, source_id)
        conn.commit()
        print(f"Chans collector complete. {created} new alerts, {duplicates} duplicates skipped.")
        return created
    except Exception as exc:
        if source_id is not None:
            mark_source_failure(conn, source_id, f"chans collector error: {exc!r}")
            conn.commit()
        print(f"Chans collector failed: {exc}")
        return 0
    finally:
        conn.close()
