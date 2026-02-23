"""
Scraper orchestration with async HTTP fetching and performance tracking.

Architecture:
- HTTP fetches use aiohttp for concurrent source fetching within each scraper type
- SQLite writes stay synchronous (single connection, no locking issues)
- feedparser parses raw text from aiohttp responses (not URLs directly)
- Performance metrics recorded to scrape_runs table
"""

import asyncio
import time
from datetime import datetime, timezone

from analytics.entity_extraction import extract_and_store_alert_entities
from analytics.ep_pipeline import process_ep_signals
from analytics.utils import utcnow
from database.init_db import get_connection
from scraper.acled_connector import run_acled_collector
from scraper.chans_collector import run_chans_collector
from scraper.darkweb_collector import run_darkweb_collector
from scraper.pastebin_monitor import run_pastebin_scraper
from scraper.reddit_scraper import run_reddit_scraper
from scraper.rss_scraper import (
    alert_exists,
    fetch_rss_feed,
    get_active_keywords,
    get_active_sources,
    match_keywords,
    parse_entry_published_at,
    run_rss_scraper,
)
from scraper.source_health import mark_source_failure, mark_source_success
from scraper.telegram_collector import run_telegram_collector

try:
    import aiohttp

    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False


def _record_scrape_run(scraper_type, started_at, total_alerts, status="completed"):
    """Record scrape run metrics to scrape_runs table."""
    try:
        conn = get_connection()
        completed_at = utcnow().strftime("%Y-%m-%d %H:%M:%S")
        duration = time.time() - started_at
        aps = total_alerts / duration if duration > 0 else 0.0

        conn.execute(
            """INSERT INTO scrape_runs
            (started_at, completed_at, scraper_type, total_alerts,
             duration_seconds, alerts_per_second, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.fromtimestamp(started_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                completed_at,
                scraper_type,
                total_alerts,
                round(duration, 2),
                round(aps, 2),
                status,
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Warning: Could not record scrape run: {e}")


def _build_run_frequency_snapshot():
    """Create a run-level frequency snapshot to keep scoring order-independent."""
    from analytics.risk_scoring import build_frequency_snapshot

    conn = get_connection()
    try:
        keyword_rows = conn.execute("SELECT id FROM keywords WHERE active = 1").fetchall()
        keyword_ids = [row["id"] for row in keyword_rows]
        return build_frequency_snapshot(conn, keyword_ids=keyword_ids)
    finally:
        conn.close()


# Concurrency control: limit parallel requests to avoid overwhelming targets
_MAX_CONCURRENT_REQUESTS = 10
_semaphore = None
_ASYNC_FETCH_RETRIES = 2
_ASYNC_FETCH_TIMEOUT_SECONDS = 25
_RSS_FETCH_HEADERS = {
    "User-Agent": "ProtectiveIntelAssistant/0.1 (+https://localhost)",
    "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5",
}


def _get_semaphore():
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(_MAX_CONCURRENT_REQUESTS)
    return _semaphore


async def _fetch_url_async(
    session,
    url,
    timeout=_ASYNC_FETCH_TIMEOUT_SECONDS,
    retries=_ASYNC_FETCH_RETRIES,
):
    """Fetch a URL asynchronously with concurrency limiting and lightweight retry."""
    attempts = max(1, int(retries))
    for attempt in range(1, attempts + 1):
        try:
            async with _get_semaphore():
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                ) as resp:
                    if resp.status == 404:
                        print(f"Async fetch HTTP 404 for {url}")
                        return None
                    if resp.status in {429, 500, 502, 503, 504} and attempt < attempts:
                        await asyncio.sleep(0.75 * attempt)
                        continue
                    if resp.status >= 400:
                        print(f"Async fetch HTTP {resp.status} for {url}")
                        return None
                    text = await resp.text()
                    if text:
                        return text
                    if attempt < attempts:
                        await asyncio.sleep(0.75 * attempt)
                        continue
                    return None
        except Exception as e:
            if attempt < attempts:
                await asyncio.sleep(0.75 * attempt)
                continue
            print(
                f"Async fetch error for {url}: "
                f"{type(e).__name__}: {e!r}"
            )
            return None
    return None


def _make_aiohttp_session():
    """
    Build an aiohttp session with larger header limits for feeds that emit long headers.
    Falls back to defaults if the installed aiohttp version lacks these parameters.
    """
    try:
        return aiohttp.ClientSession(
            headers=_RSS_FETCH_HEADERS,
            max_line_size=65536,
            max_field_size=65536,
        )
    except TypeError:
        return aiohttp.ClientSession(headers=_RSS_FETCH_HEADERS)


async def run_rss_scraper_async(frequency_snapshot=None):
    """
    Async RSS scraper: fetch all RSS feeds concurrently via aiohttp,
    then parse and process synchronously.
    """
    import feedparser

    from analytics.dedup import check_duplicate
    from analytics.risk_scoring import (
        build_frequency_snapshot,
        increment_keyword_frequency,
        score_alert,
    )

    conn = get_connection()
    keywords = get_active_keywords(conn)
    if frequency_snapshot is None:
        frequency_snapshot = build_frequency_snapshot(
            conn, keyword_ids=[keyword["id"] for keyword in keywords]
        )
    sources = get_active_sources(conn, "rss")
    new_alerts = 0
    duplicates = 0

    # Fetch all feeds concurrently
    async with _make_aiohttp_session() as session:
        tasks = [_fetch_url_async(session, s["url"]) for s in sources]
        raw_responses = await asyncio.gather(*tasks)

    # Process each feed synchronously (SQLite writes)
    for source, raw_text in zip(sources, raw_responses):
        parsed_entries = []
        failure_reason = "no feed entries returned"
        if raw_text:
            print(f"Processing: {source['name']}")
            feed = feedparser.parse(raw_text)
            parsed_entries = [
                {
                    "title": entry.get("title", ""),
                    "content": entry.get("summary", entry.get("description", "")),
                    "url": entry.get("link", ""),
                    "published": parse_entry_published_at(entry),
                }
                for entry in feed.entries
            ]
            if not parsed_entries:
                failure_reason = "async parse produced no entries"
                print(
                    f"Async parse returned no entries for {source['name']}; "
                    "trying sync RSS fallback."
                )
        if not parsed_entries:
            if not raw_text:
                failure_reason = "async fetch failed"
                print(f"Async fetch failed for {source['name']}; trying sync RSS fallback.")
            try:
                parsed_entries = fetch_rss_feed(source["url"])
            except Exception as e:
                failure_reason = f"sync fallback exception: {type(e).__name__}: {e}"
                mark_source_failure(conn, source["id"], failure_reason)
                print(f"Skipping {source['name']} (fallback failed): {e}")
                continue
            if not parsed_entries:
                failure_reason = "sync fallback returned no entries"
                mark_source_failure(conn, source["id"], failure_reason)
                print(f"Skipping {source['name']} (no entries from fallback)")
                continue

        mark_source_success(conn, source["id"])
        for entry in parsed_entries:
            title = entry.get("title", "")
            content = entry.get("content", "")
            url = entry.get("url", "")
            published_at = entry.get("published")
            combined_text = f"{title} {content}"
            matches = match_keywords(combined_text, keywords)

            for keyword in matches:
                if not alert_exists(conn, source["id"], keyword["id"], url):
                    content_hash, duplicate_of = check_duplicate(conn, title, content)
                    conn.execute(
                        """INSERT INTO alerts
                           (source_id, keyword_id, title, content, url, matched_term,
                            content_hash, duplicate_of, published_at, severity)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            source["id"],
                            keyword["id"],
                            title,
                            content[:2000],
                            url,
                            keyword["term"],
                            content_hash,
                            duplicate_of,
                            published_at,
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
                            published_at=published_at,
                            frequency_override=score_args[0] if score_args else None,
                            z_score_override=score_args[1] if score_args else None,
                        )
                        extract_and_store_alert_entities(conn, alert_id, f"{title}\n{content}")
                        process_ep_signals(
                            conn,
                            alert_id=alert_id,
                            title=title,
                            content=content,
                            keyword_category=keyword.get("category"),
                            baseline_score=baseline_score,
                        )
                        increment_keyword_frequency(conn, keyword["id"])
                        new_alerts += 1
                    else:
                        duplicates += 1

    conn.commit()
    conn.close()
    print(f"Async RSS scrape complete. {new_alerts} new alerts, {duplicates} duplicates.")
    return new_alerts


async def run_reddit_scraper_async(frequency_snapshot=None):
    """
    Async Reddit scraper: fetch all Reddit RSS feeds concurrently.
    """
    import feedparser

    from analytics.dedup import check_duplicate
    from analytics.risk_scoring import (
        build_frequency_snapshot,
        increment_keyword_frequency,
        score_alert,
    )

    conn = get_connection()
    keywords = get_active_keywords(conn)
    if frequency_snapshot is None:
        frequency_snapshot = build_frequency_snapshot(
            conn, keyword_ids=[keyword["id"] for keyword in keywords]
        )
    sources = conn.execute(
        "SELECT id, name, url FROM sources WHERE source_type = 'reddit' AND active = 1"
    ).fetchall()
    sources = [dict(s) for s in sources]
    new_alerts = 0
    duplicates = 0

    async with _make_aiohttp_session() as session:
        tasks = [_fetch_url_async(session, s["url"]) for s in sources]
        raw_responses = await asyncio.gather(*tasks)

    for source, raw_text in zip(sources, raw_responses):
        if not raw_text:
            mark_source_failure(conn, source["id"], "async fetch failed")
            print(f"Skipping {source['name']} (fetch failed)")
            continue

        print(f"Processing: {source['name']}")
        feed = feedparser.parse(raw_text)
        entries = list(feed.entries or [])
        if not entries:
            mark_source_failure(conn, source["id"], "async parse produced no entries")
            print(f"Skipping {source['name']} (no entries)")
            continue
        mark_source_success(conn, source["id"])

        for entry in entries:
            title = entry.get("title", "")
            content = entry.get("summary", "")
            url = entry.get("link", "")
            published_at = parse_entry_published_at(entry)
            combined_text = f"{title} {content}"
            matches = match_keywords(combined_text, keywords)

            for keyword in matches:
                if not alert_exists(conn, source["id"], keyword["id"], url):
                    content_hash, duplicate_of = check_duplicate(conn, title, content)
                    conn.execute(
                        """INSERT INTO alerts
                           (source_id, keyword_id, title, content, url, matched_term,
                            content_hash, duplicate_of, published_at, severity)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            source["id"],
                            keyword["id"],
                            title,
                            content[:2000],
                            url,
                            keyword["term"],
                            content_hash,
                            duplicate_of,
                            published_at,
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
                            published_at=published_at,
                            frequency_override=score_args[0] if score_args else None,
                            z_score_override=score_args[1] if score_args else None,
                        )
                        extract_and_store_alert_entities(conn, alert_id, f"{title}\n{content}")
                        process_ep_signals(
                            conn,
                            alert_id=alert_id,
                            title=title,
                            content=content,
                            keyword_category=keyword.get("category"),
                            baseline_score=baseline_score,
                        )
                        increment_keyword_frequency(conn, keyword["id"])
                        new_alerts += 1
                    else:
                        duplicates += 1

    conn.commit()
    conn.close()
    print(f"Async Reddit scrape complete. {new_alerts} new alerts, {duplicates} duplicates.")
    return new_alerts


async def run_all_scrapers_async():
    """
    Orchestrate all async scrapers concurrently.
    RSS and Reddit run in parallel; Pastebin runs sync after (rate-limited).
    """
    frequency_snapshot = _build_run_frequency_snapshot()
    rss_task = run_rss_scraper_async(frequency_snapshot=frequency_snapshot)
    reddit_task = run_reddit_scraper_async(frequency_snapshot=frequency_snapshot)

    # RSS and Reddit concurrently
    rss_count, reddit_count = await asyncio.gather(rss_task, reddit_task)

    # Pastebin stays sync (individual paste fetches are rate-limited)
    pastebin_count = run_pastebin_scraper(frequency_snapshot=frequency_snapshot)
    acled_count = run_acled_collector(frequency_snapshot=frequency_snapshot)
    darkweb_count = run_darkweb_collector(frequency_snapshot=frequency_snapshot)
    telegram_count = run_telegram_collector(frequency_snapshot=frequency_snapshot)
    chans_count = run_chans_collector(frequency_snapshot=frequency_snapshot)

    total = (
        rss_count
        + reddit_count
        + pastebin_count
        + acled_count
        + darkweb_count
        + telegram_count
        + chans_count
    )
    return total


def run_all_scrapers():
    """
    Run all scrapers with performance tracking.
    Uses async if aiohttp is available, falls back to sync.
    Backward-compatible — run.py needs zero changes.
    """
    started_at = time.time()
    total = 0
    status = "completed"

    try:
        if ASYNC_AVAILABLE:
            print("Running scrapers (async mode)...")
            total = asyncio.run(run_all_scrapers_async())
        else:
            print("Running scrapers (sync mode — install aiohttp for async)...")
            frequency_snapshot = _build_run_frequency_snapshot()
            total += run_rss_scraper(frequency_snapshot=frequency_snapshot)
            total += run_reddit_scraper(frequency_snapshot=frequency_snapshot)
            total += run_pastebin_scraper(frequency_snapshot=frequency_snapshot)
            total += run_acled_collector(frequency_snapshot=frequency_snapshot)
            total += run_darkweb_collector(frequency_snapshot=frequency_snapshot)
            total += run_telegram_collector(frequency_snapshot=frequency_snapshot)
            total += run_chans_collector(frequency_snapshot=frequency_snapshot)
    except Exception as e:
        print(f"Scraper error: {e}")
        status = "error"

    _record_scrape_run("all", started_at, total, status)
    print(f"\nTotal new alerts across all sources: {total}")
    print(f"Duration: {time.time() - started_at:.1f}s")
    return total
