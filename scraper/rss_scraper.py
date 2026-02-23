import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import feedparser

from analytics.dedup import check_duplicate
from analytics.ep_pipeline import process_ep_signals
from analytics.entity_extraction import extract_and_store_alert_entities
from analytics.risk_scoring import (
    build_frequency_snapshot,
    increment_keyword_frequency,
    score_alert,
)
from database.init_db import get_connection
from scraper.source_health import mark_source_failure, mark_source_success


def parse_entry_published_at(entry):
    """
    Parse an RSS/Atom entry published timestamp to UTC naive string.
    Returns '%Y-%m-%d %H:%M:%S' or None.
    """
    published_text = entry.get("published") or entry.get("updated")
    if published_text:
        try:
            published_dt = parsedate_to_datetime(published_text)
            if published_dt.tzinfo is not None:
                published_dt = published_dt.astimezone(timezone.utc).replace(tzinfo=None)
            return published_dt.strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            pass

    published_parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if published_parsed:
        try:
            return datetime(*published_parsed[:6]).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return None
    return None


def fetch_rss_feed(url):
    feed = feedparser.parse(url)
    status = getattr(feed, "status", None)
    if status and int(status) >= 400:
        print(f"RSS fetch HTTP {status} for {url}")
    if getattr(feed, "bozo", 0) and not feed.entries:
        bozo_exc = getattr(feed, "bozo_exception", None)
        if bozo_exc is not None:
            print(f"RSS parse warning for {url}: {type(bozo_exc).__name__}: {bozo_exc}")
    entries = []
    for entry in feed.entries:
        entries.append(
            {
                "title": entry.get("title", ""),
                "content": entry.get("summary", entry.get("description", "")),
                "url": entry.get("link", ""),
                "published": parse_entry_published_at(entry),
            }
        )
    return entries


def match_keywords(text, keywords):
    matches = []
    text = text or ""
    text_lower = text.lower()
    for keyword in keywords:
        term = (keyword.get("term") or "").strip()
        if not term:
            continue

        # Avoid false positives for natural-language "apt" (e.g., "apt response").
        if term.lower() == "apt":
            if re.search(r"\bapt\s?\d{2,4}\b", text, flags=re.IGNORECASE):
                matches.append(keyword)
            continue

        if re.search(r"\b" + re.escape(term.lower()) + r"\b", text_lower):
            matches.append(keyword)
    return matches


def get_active_keywords(conn):
    cursor = conn.execute("SELECT id, term, category FROM keywords WHERE active = 1")
    return [dict(row) for row in cursor.fetchall()]


def get_active_sources(conn, source_type="rss"):
    cursor = conn.execute(
        "SELECT id, name, url FROM sources WHERE source_type = ? AND active = 1",
        (source_type,),
    )
    return [dict(row) for row in cursor.fetchall()]


def alert_exists(conn, source_id, keyword_id, url):
    cursor = conn.execute(
        "SELECT 1 FROM alerts WHERE source_id = ? AND keyword_id = ? AND url = ?",
        (source_id, keyword_id, url),
    )
    return cursor.fetchone() is not None


def run_rss_scraper(frequency_snapshot=None):
    conn = get_connection()
    keywords = get_active_keywords(conn)
    if frequency_snapshot is None:
        frequency_snapshot = build_frequency_snapshot(
            conn, keyword_ids=[keyword["id"] for keyword in keywords]
        )
    sources = get_active_sources(conn, "rss")
    new_alerts = 0
    duplicates = 0

    for source in sources:
        print(f"Scraping: {source['name']}")
        entries = fetch_rss_feed(source["url"])
        if not entries:
            mark_source_failure(conn, source["id"], "sync RSS returned no entries")
            continue
        mark_source_success(conn, source["id"])

        for entry in entries:
            combined_text = f"{entry['title']} {entry['content']}"
            matches = match_keywords(combined_text, keywords)

            for keyword in matches:
                if not alert_exists(conn, source["id"], keyword["id"], entry["url"]):
                    content_hash, duplicate_of = check_duplicate(
                        conn, entry["title"], entry["content"]
                    )
                    conn.execute(
                        """INSERT INTO alerts
                           (source_id, keyword_id, title, content, url, matched_term,
                            content_hash, duplicate_of, published_at, severity)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            source["id"],
                            keyword["id"],
                            entry["title"],
                            entry["content"][:2000],
                            entry["url"],
                            keyword["term"],
                            content_hash,
                            duplicate_of,
                            entry["published"],
                            "low",
                        ),
                    )
                    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

                    if duplicate_of is None:
                        score_args = frequency_snapshot.get(keyword["id"])
                        baseline_score = score_alert(
                            conn,
                            alert_id,
                            keyword["id"],
                            source["id"],
                            published_at=entry["published"],
                            frequency_override=score_args[0] if score_args else None,
                            z_score_override=score_args[1] if score_args else None,
                        )
                        extract_and_store_alert_entities(
                            conn, alert_id, f"{entry['title']}\n{entry['content']}"
                        )
                        process_ep_signals(
                            conn,
                            alert_id=alert_id,
                            title=entry["title"],
                            content=entry["content"],
                            keyword_category=keyword.get("category"),
                            baseline_score=baseline_score,
                        )
                        increment_keyword_frequency(conn, keyword["id"])
                        new_alerts += 1
                    else:
                        duplicates += 1

    conn.commit()
    conn.close()
    print(f"RSS scrape complete. {new_alerts} new alerts, {duplicates} duplicates skipped.")
    return new_alerts


if __name__ == "__main__":
    run_rss_scraper()
