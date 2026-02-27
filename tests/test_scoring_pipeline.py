from datetime import timedelta

from analytics.utils import utcnow
from analytics.risk_scoring import (
    build_frequency_snapshot,
    increment_keyword_frequency,
    score_alert,
)
from api.main import startup
from database.init_db import get_connection
from scraper.rss_scraper import match_keywords


def _get_source_and_keyword_ids():
    conn = get_connection()
    source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    keyword_id = conn.execute("SELECT id FROM keywords WHERE term = 'stalking'").fetchone()["id"]
    conn.close()
    return source_id, keyword_id


def test_recency_prefers_published_timestamp(client):
    source_id, keyword_id = _get_source_and_keyword_ids()
    conn = get_connection()
    old_published = (utcnow() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

    conn.execute(
        """INSERT INTO alerts
        (source_id, keyword_id, title, content, url, matched_term, published_at, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            source_id,
            keyword_id,
            "Published-old alert",
            "content",
            "https://example.com/published-old",
            "stalking",
            old_published,
            "low",
        ),
    )
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    score_alert(
        conn,
        alert_id,
        keyword_id,
        source_id,
        created_at=utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        published_at=old_published,
        frequency_override=1.0,
        z_score_override=0.0,
    )
    recency_factor = conn.execute(
        """SELECT recency_factor FROM alert_scores
        WHERE alert_id = ? ORDER BY id DESC LIMIT 1""",
        (alert_id,),
    ).fetchone()["recency_factor"]
    conn.commit()
    conn.close()

    assert recency_factor == 0.1


def test_frequency_snapshot_keeps_same_keyword_scores_order_independent(client):
    source_id, keyword_id = _get_source_and_keyword_ids()
    conn = get_connection()
    snapshot = build_frequency_snapshot(conn, keyword_ids=[keyword_id])

    alert_ids = []
    for idx in range(2):
        conn.execute(
            """INSERT INTO alerts
            (source_id, keyword_id, title, content, url, matched_term, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                source_id,
                keyword_id,
                f"Order test {idx}",
                "same content",
                f"https://example.com/order-{idx}",
                "stalking",
                "low",
            ),
        )
        alert_ids.append(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

    for alert_id in alert_ids:
        score_alert(
            conn,
            alert_id,
            keyword_id,
            source_id,
            frequency_override=snapshot[keyword_id][0],
            z_score_override=snapshot[keyword_id][1],
        )
        increment_keyword_frequency(conn, keyword_id)

    scores = conn.execute(
        "SELECT risk_score FROM alerts WHERE id IN (?, ?) ORDER BY id",
        (alert_ids[0], alert_ids[1]),
    ).fetchall()
    conn.commit()
    conn.close()

    assert scores[0]["risk_score"] == scores[1]["risk_score"]


def test_apt_keyword_avoids_plain_language_false_positives():
    keywords = [{"id": 1, "term": "APT", "category": "threat_actor"}]
    assert match_keywords("This is an apt response to the threat.", keywords) == []
    assert len(match_keywords("Investigation references APT29 activity.", keywords)) == 1


def test_api_startup_does_not_overwrite_keyword_weights(client):
    conn = get_connection()
    conn.execute("UPDATE keywords SET weight = 1.7 WHERE term = 'stalking'")
    conn.commit()
    conn.close()

    startup()

    conn = get_connection()
    weight = conn.execute("SELECT weight FROM keywords WHERE term = 'stalking'").fetchone()[
        "weight"
    ]
    conn.close()

    assert weight == 1.7
