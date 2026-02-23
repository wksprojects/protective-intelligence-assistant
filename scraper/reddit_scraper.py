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
from scraper.rss_scraper import (
    alert_exists,
    get_active_keywords,
    match_keywords,
    parse_entry_published_at,
)
from scraper.source_health import mark_source_failure, mark_source_success


def fetch_reddit_rss(url):
    feed = feedparser.parse(url)
    entries = []
    for entry in feed.entries:
        entries.append(
            {
                "title": entry.get("title", ""),
                "content": entry.get("summary", ""),
                "url": entry.get("link", ""),
                "published": parse_entry_published_at(entry),
            }
        )
    return entries


def get_reddit_sources(conn):
    cursor = conn.execute(
        "SELECT id, name, url FROM sources WHERE source_type = 'reddit' AND active = 1"
    )
    return [dict(row) for row in cursor.fetchall()]


def run_reddit_scraper(frequency_snapshot=None):
    conn = get_connection()
    keywords = get_active_keywords(conn)
    if frequency_snapshot is None:
        frequency_snapshot = build_frequency_snapshot(
            conn, keyword_ids=[keyword["id"] for keyword in keywords]
        )
    sources = get_reddit_sources(conn)
    new_alerts = 0
    duplicates = 0

    for source in sources:
        print(f"Scraping: {source['name']}")
        entries = fetch_reddit_rss(source["url"])
        if not entries:
            mark_source_failure(conn, source["id"], "sync Reddit RSS returned no entries")
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
    print(f"Reddit scrape complete. {new_alerts} new alerts, {duplicates} duplicates skipped.")
    return new_alerts


if __name__ == "__main__":
    run_reddit_scraper()
