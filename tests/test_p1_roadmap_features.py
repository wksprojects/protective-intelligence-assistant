from datetime import timedelta

from analytics.utils import utcnow
from database.init_db import get_connection
from scraper.source_health import mark_source_failure, mark_source_skipped, mark_source_success


def _insert_alert(
    conn,
    source_id,
    keyword_id,
    title,
    url,
    matched_term,
    published_at=None,
):
    conn.execute(
        """INSERT INTO alerts
        (source_id, keyword_id, title, content, url, matched_term, severity, published_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            source_id,
            keyword_id,
            title,
            "seed content",
            url,
            matched_term,
            "low",
            published_at or utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def test_source_health_failure_threshold_and_recovery(client, monkeypatch):
    monkeypatch.setenv("PI_SOURCE_AUTO_DISABLE", "1")
    monkeypatch.setenv("PI_SOURCE_FAIL_DISABLE_THRESHOLD", "2")

    conn = get_connection()
    source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]

    mark_source_failure(conn, source_id, "timeout")
    row = conn.execute(
        "SELECT fail_streak, active, last_status FROM sources WHERE id = ?",
        (source_id,),
    ).fetchone()
    assert row["fail_streak"] == 1
    assert row["active"] == 1
    assert row["last_status"] == "error"

    mark_source_failure(conn, source_id, "timeout again")
    row = conn.execute(
        "SELECT fail_streak, active, disabled_reason, last_error FROM sources WHERE id = ?",
        (source_id,),
    ).fetchone()
    assert row["fail_streak"] == 2
    assert row["active"] == 0
    assert "auto-disabled" in (row["disabled_reason"] or "")
    assert "timeout again" in (row["last_error"] or "")

    mark_source_success(conn, source_id)
    row = conn.execute(
        "SELECT fail_streak, active, last_status, last_error, disabled_reason FROM sources WHERE id = ?",
        (source_id,),
    ).fetchone()
    conn.commit()
    conn.close()

    assert row["fail_streak"] == 0
    assert row["active"] == 1
    assert row["last_status"] == "ok"
    assert row["last_error"] is None
    assert row["disabled_reason"] is None


def test_source_health_endpoint_reflects_skipped_state(client):
    conn = get_connection()
    source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    mark_source_skipped(conn, source_id, "credentials not configured")
    conn.commit()
    conn.close()

    response = client.get("/analytics/source-health")
    assert response.status_code == 200
    payload = response.json()
    source = next(item for item in payload if item["id"] == source_id)
    assert source["last_status"] == "skipped"
    assert "credentials not configured" in (source["last_error"] or "")


def test_source_presets_endpoint_returns_location_previews(client):
    response = client.get(
        "/analytics/source-presets",
        params={"horizon_days": 30, "max_contexts_per_preset": 2},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["horizon_days"] == 30
    assert isinstance(payload["presets"], list)
    assert len(payload["presets"]) > 0

    location_preset = next((item for item in payload["presets"] if item["scope"] == "location"), None)
    assert location_preset is not None
    assert len(location_preset["preview"]) > 0
    first_preview = location_preset["preview"][0]
    assert first_preview["scope_type"] == "location"
    assert first_preview["source_type"] == "reddit"
    assert first_preview["suggested_name"]


def test_soi_threads_endpoint_clusters_related_alerts(client):
    now = utcnow()
    conn = get_connection()
    rss_source = conn.execute(
        "SELECT id FROM sources WHERE source_type = 'rss' AND active = 1 ORDER BY id LIMIT 1"
    ).fetchone()["id"]
    reddit_source = conn.execute(
        "SELECT id FROM sources WHERE source_type = 'reddit' AND active = 1 ORDER BY id LIMIT 1"
    ).fetchone()["id"]
    keyword_id = conn.execute("SELECT id FROM keywords WHERE term = 'death threat'").fetchone()["id"]

    first_alert = _insert_alert(
        conn,
        source_id=rss_source,
        keyword_id=keyword_id,
        title="First correlated signal",
        url="https://example.com/thread-1",
        matched_term="death threat",
        published_at=(now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
    )
    second_alert = _insert_alert(
        conn,
        source_id=reddit_source,
        keyword_id=keyword_id,
        title="Second correlated signal",
        url="https://example.com/thread-2",
        matched_term="death threat",
        published_at=(now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
    )

    conn.execute(
        """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value)
        VALUES (?, 'actor_handle', ?)""",
        (first_alert, "@demo_actor"),
    )
    conn.execute(
        """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value)
        VALUES (?, 'actor_handle', ?)""",
        (second_alert, "@demo_actor"),
    )
    conn.commit()
    conn.close()

    response = client.get(
        "/analytics/soi-threads",
        params={"days": 7, "window_hours": 72, "min_cluster_size": 2},
    )
    assert response.status_code == 200
    threads = response.json()
    assert len(threads) > 0

    matched = False
    for thread in threads:
        alert_ids = {row["alert_id"] for row in thread.get("timeline", [])}
        if first_alert in alert_ids and second_alert in alert_ids:
            matched = True
            break
    assert matched


def test_signal_quality_endpoint_aggregates_precision(client):
    conn = get_connection()
    source_one = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    source_two = conn.execute(
        "SELECT id FROM sources WHERE id != ? ORDER BY id LIMIT 1",
        (source_one,),
    ).fetchone()["id"]
    keyword_pi = conn.execute("SELECT id FROM keywords WHERE term = 'death threat'").fetchone()["id"]
    keyword_travel = conn.execute("SELECT id FROM keywords WHERE term = 'travel advisory'").fetchone()["id"]

    alert_tp = _insert_alert(
        conn,
        source_id=source_one,
        keyword_id=keyword_pi,
        title="TP sample",
        url="https://example.com/quality-1",
        matched_term="death threat",
    )
    alert_fp = _insert_alert(
        conn,
        source_id=source_one,
        keyword_id=keyword_pi,
        title="FP sample",
        url="https://example.com/quality-2",
        matched_term="death threat",
    )
    alert_tp_two = _insert_alert(
        conn,
        source_id=source_two,
        keyword_id=keyword_travel,
        title="TP travel sample",
        url="https://example.com/quality-3",
        matched_term="travel advisory",
    )
    conn.execute(
        "INSERT INTO dispositions (alert_id, status, rationale, user) VALUES (?, ?, ?, ?)",
        (alert_tp, "true_positive", "confirmed", "test"),
    )
    conn.execute(
        "INSERT INTO dispositions (alert_id, status, rationale, user) VALUES (?, ?, ?, ?)",
        (alert_fp, "false_positive", "noise", "test"),
    )
    conn.execute(
        "INSERT INTO dispositions (alert_id, status, rationale, user) VALUES (?, ?, ?, ?)",
        (alert_tp_two, "true_positive", "confirmed", "test"),
    )
    conn.commit()
    conn.close()

    response = client.get("/analytics/signal-quality", params={"window_days": 30})
    assert response.status_code == 200
    payload = response.json()

    assert payload["overall_window"]["classified"] == 3
    assert payload["overall_window"]["true_positive"] == 2
    assert payload["overall_window"]["false_positive"] == 1
    assert payload["overall_window"]["precision"] == 0.6667

    first_source_metrics = next(
        row for row in payload["by_source_window"] if row["source_id"] == source_one
    )
    assert first_source_metrics["classified"] == 2
    assert first_source_metrics["precision"] == 0.5


def test_telegram_and_chans_scrape_endpoints_respect_env_gates(client, monkeypatch):
    monkeypatch.setenv("PI_ENABLE_TELEGRAM_COLLECTOR", "0")
    monkeypatch.setenv("PI_ENABLE_CHANS_COLLECTOR", "0")

    telegram = client.post("/scrape/telegram")
    chans = client.post("/scrape/chans")
    assert telegram.status_code == 200
    assert chans.status_code == 200
    assert telegram.json()["ingested"] == 0
    assert chans.json()["ingested"] == 0

    conn = get_connection()
    telegram_source = conn.execute(
        "SELECT last_status FROM sources WHERE source_type = 'telegram' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    chans_source = conn.execute(
        "SELECT last_status FROM sources WHERE source_type = 'chans' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    assert telegram_source is not None
    assert chans_source is not None
    assert telegram_source["last_status"] == "skipped"
    assert chans_source["last_status"] == "skipped"


def test_telegram_and_chans_scrape_endpoints_ingest_fixtures(client, monkeypatch):
    monkeypatch.setenv("PI_ENABLE_TELEGRAM_COLLECTOR", "1")
    monkeypatch.setenv("PI_ENABLE_CHANS_COLLECTOR", "1")

    telegram = client.post("/scrape/telegram")
    chans = client.post("/scrape/chans")
    assert telegram.status_code == 200
    assert chans.status_code == 200
    assert telegram.json()["ingested"] >= 1
    assert chans.json()["ingested"] >= 1

    conn = get_connection()
    telegram_alerts = conn.execute(
        """SELECT COUNT(*) AS count
        FROM alerts a
        JOIN sources s ON s.id = a.source_id
        WHERE s.source_type = 'telegram'"""
    ).fetchone()["count"]
    chans_alerts = conn.execute(
        """SELECT COUNT(*) AS count
        FROM alerts a
        JOIN sources s ON s.id = a.source_id
        WHERE s.source_type = 'chans'"""
    ).fetchone()["count"]
    telegram_status = conn.execute(
        "SELECT last_status FROM sources WHERE source_type = 'telegram' ORDER BY id DESC LIMIT 1"
    ).fetchone()["last_status"]
    chans_status = conn.execute(
        "SELECT last_status FROM sources WHERE source_type = 'chans' ORDER BY id DESC LIMIT 1"
    ).fetchone()["last_status"]
    conn.close()

    assert telegram_alerts >= 1
    assert chans_alerts >= 1
    assert telegram_status == "ok"
    assert chans_status == "ok"
