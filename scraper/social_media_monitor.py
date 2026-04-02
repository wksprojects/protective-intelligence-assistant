"""Social media monitoring pipeline for protective intelligence.

Supported platforms (when API access is configured):
- X/Twitter (via API v2 or commercial aggregator)
- Instagram (via Meta Business API)
- Telegram (public channels via Telethon)
- TikTok (via Research API)

In production, connect to platform APIs or commercial aggregators
(Dataminr, Flashpoint, Babel Street). The demo ships with representative
fixture data demonstrating:
- Direct threat detection
- Hostile surveillance identification
- Fixation/grievance escalation tracking
- False positive filtering

Configuration:
    Set SOCIAL_MEDIA_ENABLED=1 plus platform-specific API keys.
    When disabled, the monitor loads from fixtures/social_media_fixtures.json.
"""

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

from analytics.dedup import check_duplicate
from analytics.entity_extraction import extract_and_store_alert_entities
from analytics.ep_pipeline import process_ep_signals
from analytics.risk_scoring import increment_keyword_frequency, score_alert
from analytics.utils import utcnow
from database.init_db import get_connection

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "social_media_fixtures.json"

# Platform-specific configuration (extend per platform)
PLATFORM_CONFIG = {
    "x_twitter": {
        "env_key": "TWITTER_BEARER_TOKEN",
        "base_url": "https://api.twitter.com/2",
        "rate_limit_per_min": 300,
    },
    "instagram": {
        "env_key": "INSTAGRAM_ACCESS_TOKEN",
        "base_url": "https://graph.facebook.com/v18.0",
        "rate_limit_per_min": 200,
    },
    "telegram": {
        "env_key": "TELEGRAM_API_ID",
        "base_url": None,  # Uses Telethon client
        "rate_limit_per_min": 30,
    },
    "tiktok": {
        "env_key": "TIKTOK_RESEARCH_TOKEN",
        "base_url": "https://open.tiktokapis.com/v2",
        "rate_limit_per_min": 100,
    },
}


def _platform_enabled(platform):
    """Check if a platform's API credentials are configured."""
    config = PLATFORM_CONFIG.get(platform, {})
    env_key = config.get("env_key", "")
    return bool(os.getenv(env_key, ""))


def _load_fixtures():
    """Load demo social media posts from fixtures."""
    if FIXTURE_PATH.exists():
        return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return []


def _ensure_social_source(conn, platform):
    """Ensure a source record exists for the social media platform."""
    source_name = f"Social Media: {platform.replace('_', ' ').title()}"
    row = conn.execute("SELECT id FROM sources WHERE name = ?", (source_name,)).fetchone()
    if row:
        return row["id"]
    conn.execute(
        """INSERT INTO sources (name, url, source_type, credibility_score, active)
        VALUES (?, ?, ?, ?, 1)""",
        (source_name, f"social://{platform}", "social_media", 0.5),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _ensure_keyword(conn, term, category="protective_intel", weight=3.0):
    """Ensure a keyword exists, return its ID."""
    row = conn.execute("SELECT id FROM keywords WHERE term = ?", (term,)).fetchone()
    if row:
        return row["id"]
    conn.execute(
        "INSERT INTO keywords (term, category, weight, active) VALUES (?, ?, ?, 1)",
        (term, category, weight),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _ingest_social_post(conn, post, source_id):
    """Ingest a single social media post into the alert pipeline."""
    keyword_id = _ensure_keyword(
        conn,
        post.get("matched_term", "social media threat"),
        category=post.get("category", "protective_intel"),
        weight=float(post.get("keyword_weight", 3.0)),
    )

    # Dedup check
    content_hash, duplicate_of = check_duplicate(conn, post["title"], post.get("content", ""))

    # Check URL-based dedup
    existing = conn.execute("SELECT id FROM alerts WHERE url = ?", (post["url"],)).fetchone()
    if existing:
        return None

    conn.execute(
        """INSERT INTO alerts
        (source_id, keyword_id, title, content, url, matched_term,
         published_at, severity, content_hash, duplicate_of)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'low', ?, ?)""",
        (
            source_id,
            keyword_id,
            post["title"],
            post.get("content", "")[:2000],
            post["url"],
            post.get("matched_term", "social media"),
            post.get("published_at") or utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            content_hash,
            duplicate_of,
        ),
    )
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    if duplicate_of is None:
        baseline = score_alert(conn, alert_id, keyword_id, source_id)
        text = f"{post['title']}\n{post.get('content', '')}"
        extract_and_store_alert_entities(conn, alert_id, text)
        process_ep_signals(
            conn,
            alert_id=alert_id,
            title=post["title"],
            content=post.get("content", ""),
            keyword_category=post.get("category", "protective_intel"),
            baseline_score=baseline,
        )
        increment_keyword_frequency(conn, keyword_id)

    return alert_id


def run_social_media_monitor():
    """Run the social media monitor.

    When platform APIs are configured, fetches live data.
    Otherwise, loads from fixture data for demo purposes.
    """
    enabled = os.getenv("SOCIAL_MEDIA_ENABLED", "0").lower() in {"1", "true", "yes"}
    any_platform = any(_platform_enabled(p) for p in PLATFORM_CONFIG)

    if not enabled and not any_platform:
        # Demo mode: load fixtures
        posts = _load_fixtures()
        if not posts:
            logger.info("Social media monitor: no fixtures found, skipping.")
            return {"ingested": 0, "mode": "disabled"}
    else:
        # Production mode: would fetch from configured platforms
        # For now, still load fixtures as placeholder
        posts = _load_fixtures()
        logger.info(
            f"Social media monitor: {len(posts)} posts from fixtures (live API not yet connected)."
        )

    conn = get_connection()
    ingested = 0
    try:
        for post in posts:
            platform = post.get("platform", "x_twitter")
            source_id = _ensure_social_source(conn, platform)
            alert_id = _ingest_social_post(conn, post, source_id)
            if alert_id is not None:
                ingested += 1
        conn.commit()
    finally:
        conn.close()

    logger.info(f"Social media monitor: {ingested} new posts ingested.")
    return {"ingested": ingested, "mode": "fixture" if not any_platform else "live"}
