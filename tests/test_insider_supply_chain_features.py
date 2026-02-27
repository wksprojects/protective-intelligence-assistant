from datetime import timedelta

from analytics.utils import utcnow
from database.init_db import get_connection


def _insert_alert(conn, source_id, keyword_id, title, url, matched_term, published_at=None):
    conn.execute(
        """INSERT INTO alerts
        (source_id, keyword_id, title, content, url, matched_term, severity, published_at, risk_score, ors_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            source_id,
            keyword_id,
            title,
            "seed content",
            url,
            matched_term,
            "medium",
            published_at or utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            72.0,
            72.0,
        ),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def test_insider_scrape_and_analytics_endpoint(client):
    response = client.post("/scrape/insider")
    assert response.status_code == 200
    assert response.json()["ingested"] >= 1

    analytics_response = client.get("/analytics/insider-risk")
    assert analytics_response.status_code == 200
    payload = analytics_response.json()
    assert isinstance(payload, list)
    assert len(payload) >= 1
    top = payload[0]
    assert "subject_id" in top
    assert "irs_score" in top
    assert isinstance(top.get("reason_codes"), list)
    assert isinstance(top.get("signal_breakdown"), dict)

    conn = get_connection()
    source = conn.execute(
        "SELECT last_status FROM sources WHERE source_type = 'insider' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert source is not None
    assert source["last_status"] == "ok"


def test_supply_chain_scrape_endpoint_respects_env_gate(client, monkeypatch):
    monkeypatch.setenv("PI_ENABLE_SUPPLY_CHAIN", "0")
    response = client.post("/scrape/supply-chain")
    assert response.status_code == 200
    assert response.json()["ingested"] == 0

    conn = get_connection()
    source = conn.execute(
        "SELECT last_status FROM sources WHERE source_type = 'supply_chain' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert source is not None
    assert source["last_status"] == "skipped"


def test_supply_chain_scrape_and_analytics_endpoint(client, monkeypatch):
    monkeypatch.setenv("PI_ENABLE_SUPPLY_CHAIN", "1")
    response = client.post("/scrape/supply-chain")
    assert response.status_code == 200
    assert response.json()["ingested"] >= 1

    analytics_response = client.get("/analytics/supply-chain-risk")
    assert analytics_response.status_code == 200
    payload = analytics_response.json()
    assert isinstance(payload, list)
    assert len(payload) >= 1
    top = payload[0]
    assert "profile_id" in top
    assert "vendor_risk_score" in top
    assert isinstance(top.get("reason_codes"), list)
    assert isinstance(top.get("factor_breakdown"), dict)

    conn = get_connection()
    source = conn.execute(
        "SELECT last_status FROM sources WHERE source_type = 'supply_chain' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert source is not None
    assert source["last_status"] == "ok"


def test_insider_threads_converge_with_external_signal(client):
    insider_ingest = client.post("/scrape/insider")
    assert insider_ingest.status_code == 200
    assert insider_ingest.json()["ingested"] >= 1

    conn = get_connection()
    insider_handle_row = conn.execute(
        """SELECT ae.entity_value
        FROM alert_entities ae
        JOIN alerts a ON a.id = ae.alert_id
        JOIN sources s ON s.id = a.source_id
        WHERE s.source_type = 'insider'
          AND ae.entity_type = 'actor_handle'
        ORDER BY ae.id
        LIMIT 1"""
    ).fetchone()
    assert insider_handle_row is not None

    rss_source_id = conn.execute(
        "SELECT id FROM sources WHERE source_type = 'rss' ORDER BY id LIMIT 1"
    ).fetchone()["id"]
    keyword_id = conn.execute("SELECT id FROM keywords WHERE term = 'death threat'").fetchone()["id"]
    alert_id = _insert_alert(
        conn,
        source_id=rss_source_id,
        keyword_id=keyword_id,
        title="External corroboration for insider handle",
        url="https://example.com/insider-cross-domain",
        matched_term="death threat",
        published_at=(utcnow() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
    )
    conn.execute(
        """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
        VALUES (?, 'actor_handle', ?, CURRENT_TIMESTAMP)""",
        (alert_id, insider_handle_row["entity_value"]),
    )
    conn.commit()
    conn.close()

    response = client.get(
        "/analytics/soi-threads",
        params={"days": 7, "window_hours": 72, "min_cluster_size": 2},
    )
    assert response.status_code == 200
    threads = response.json()

    matched = False
    for thread in threads:
        source_types = set(thread.get("source_types") or [])
        if {"insider", "rss"}.issubset(source_types):
            if "shared_actor_handle" in (thread.get("reason_codes") or []):
                matched = True
                break
    assert matched


def test_soi_threads_link_user_and_vendor_entities(client, monkeypatch):
    insider_ingest = client.post("/scrape/insider")
    assert insider_ingest.status_code == 200
    assert insider_ingest.json()["ingested"] >= 1

    monkeypatch.setenv("PI_ENABLE_SUPPLY_CHAIN", "1")
    supply_ingest = client.post("/scrape/supply-chain")
    assert supply_ingest.status_code == 200
    assert supply_ingest.json()["ingested"] >= 1

    conn = get_connection()
    user_row = conn.execute(
        """SELECT ae.entity_value
        FROM alert_entities ae
        JOIN alerts a ON a.id = ae.alert_id
        JOIN sources s ON s.id = a.source_id
        WHERE s.source_type = 'insider'
          AND ae.entity_type = 'user_id'
        ORDER BY ae.id
        LIMIT 1"""
    ).fetchone()
    assert user_row is not None

    rss_source_id = conn.execute(
        "SELECT id FROM sources WHERE source_type = 'rss' ORDER BY id LIMIT 1"
    ).fetchone()["id"]
    keyword_id = conn.execute("SELECT id FROM keywords WHERE term = 'death threat'").fetchone()["id"]
    alert_id = _insert_alert(
        conn,
        source_id=rss_source_id,
        keyword_id=keyword_id,
        title="External event tied to insider user identifier",
        url="https://example.com/insider-user-id-cross-domain",
        matched_term="death threat",
        published_at=(utcnow() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
    )
    conn.execute(
        """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
        VALUES (?, 'user_id', ?, CURRENT_TIMESTAMP)""",
        (alert_id, user_row["entity_value"]),
    )
    conn.commit()
    conn.close()

    response = client.get(
        "/analytics/soi-threads",
        params={"days": 7, "window_hours": 72, "min_cluster_size": 2},
    )
    assert response.status_code == 200
    threads = response.json()

    user_linked = False
    vendor_linked = False
    for thread in threads:
        reasons = set(thread.get("reason_codes") or [])
        source_types = set(thread.get("source_types") or [])
        if {"insider", "rss"}.issubset(source_types) and "shared_user_id" in reasons:
            user_linked = True
        if {"insider", "supply_chain"}.issubset(source_types) and "shared_vendor_id" in reasons:
            vendor_linked = True

    assert user_linked
    assert vendor_linked
