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


def test_insider_scrape_returns_503_on_collector_error(client, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("synthetic insider failure")

    monkeypatch.setattr("collectors.insider_telemetry.ingest_insider_events", _boom)
    response = client.post("/scrape/insider")
    assert response.status_code == 503
    assert "insider_telemetry collector error" in response.json()["detail"]

    conn = get_connection()
    source = conn.execute(
        "SELECT last_status FROM sources WHERE source_type = 'insider' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert source is not None
    assert source["last_status"] == "error"


def test_supply_chain_scrape_returns_503_on_collector_error(client, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("synthetic supply-chain failure")

    monkeypatch.setenv("PI_ENABLE_SUPPLY_CHAIN", "1")
    monkeypatch.setattr("collectors.supply_chain.ingest_supply_chain_profiles", _boom)
    response = client.post("/scrape/supply-chain")
    assert response.status_code == 503
    assert "supply_chain_scaffold collector error" in response.json()["detail"]

    conn = get_connection()
    source = conn.execute(
        "SELECT last_status FROM sources WHERE source_type = 'supply_chain' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert source is not None
    assert source["last_status"] == "error"


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


def test_fixture_collectors_do_not_duplicate_sources(client, monkeypatch):
    from collectors.insider_telemetry import SOURCE_NAME as INSIDER_SOURCE_NAME
    from collectors.supply_chain import SOURCE_NAME as SUPPLY_SOURCE_NAME

    insider_resp = client.post("/scrape/insider")
    assert insider_resp.status_code == 200
    assert insider_resp.json()["ingested"] >= 1

    monkeypatch.setenv("PI_ENABLE_SUPPLY_CHAIN", "1")
    supply_resp = client.post("/scrape/supply-chain")
    assert supply_resp.status_code == 200
    assert supply_resp.json()["ingested"] >= 1

    conn = get_connection()
    insider_sources = conn.execute(
        "SELECT COUNT(*) AS count FROM sources WHERE source_type = 'insider' AND name = ?",
        (INSIDER_SOURCE_NAME,),
    ).fetchone()["count"]
    supply_sources = conn.execute(
        "SELECT COUNT(*) AS count FROM sources WHERE source_type = 'supply_chain' AND name = ?",
        (SUPPLY_SOURCE_NAME,),
    ).fetchone()["count"]
    conn.close()

    assert insider_sources == 1
    assert supply_sources == 1


def test_ingest_insider_events_endpoint(client):
    response = client.post(
        "/ingest/insider-events",
        json={
            "source_name": "Insider Telemetry (Synthetic EDR Feed)",
            "source_url": "insider://edr-fixture-adapter",
            "events": [
                {
                    "event_id": "edr-evt-001",
                    "subject_id": "EMP-9901",
                    "subject_name": "Casey Rivers",
                    "timestamp": "2026-02-27 03:14:00",
                    "title": "Bulk engineering archive transfer",
                    "summary": "Large archive transfer after midnight from privileged endpoint.",
                    "signals": {
                        "access_pattern_deviation": 0.86,
                        "off_hours_activity": 0.92,
                        "resource_sensitivity_access": 0.88,
                        "bulk_data_download_gb": 48.0,
                        "usb_write_gb": 14.0,
                        "cloud_upload_gb": 39.0,
                        "badge_login_mismatch": 1.0,
                        "policy_violations": 0.9,
                        "communication_metadata_shift": 0.67,
                        "cumulative_risk_acceleration": 0.84,
                    },
                    "related_entities": [
                        {"entity_type": "user_id", "entity_value": "emp-9901"},
                        {"entity_type": "device_id", "entity_value": "lpt-77"},
                        {"entity_type": "vendor_id", "entity_value": "sc-004"},
                    ],
                },
                {"event_id": "edr-evt-invalid", "subject_name": "Missing Subject"},
            ],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["processed"] == 2
    assert payload["ingested"] == 1
    assert payload["updated"] == 0
    assert payload["invalid"] == 1
    assert payload["subjects_assessed"] == 1

    analytics = client.get("/analytics/insider-risk", params={"limit": 10})
    assert analytics.status_code == 200
    rows = analytics.json()
    subject_row = next((row for row in rows if row["subject_id"] == "EMP-9901"), None)
    assert subject_row is not None
    assert subject_row["irs_score"] >= 55.0
    assert len(subject_row["reason_codes"]) > 0

    conn = get_connection()
    source = conn.execute(
        "SELECT source_type, last_status FROM sources WHERE name = ? ORDER BY id DESC LIMIT 1",
        ("Insider Telemetry (Synthetic EDR Feed)",),
    ).fetchone()
    conn.close()
    assert source is not None
    assert source["source_type"] == "insider"
    assert source["last_status"] == "ok"


def test_ingest_supply_chain_profiles_endpoint(client):
    response = client.post(
        "/ingest/supply-chain-profiles",
        json={
            "source_name": "Supply Chain Risk (Synthetic TPRM Feed)",
            "source_url": "supply-chain://tprm-fixture-adapter",
            "profiles": [
                {
                    "external_id": "ven-8472",
                    "name": "HarborLine Logistics",
                    "domain": "harborline.example",
                    "country": "IR",
                    "factors": {
                        "geographic_risk": 0.93,
                        "single_point_of_failure": 0.88,
                        "access_privilege_scope": 0.74,
                        "data_sensitivity_exposure": 0.69,
                        "compliance_posture": 0.32,
                    },
                    "shared_entities": [{"entity_type": "vendor_id", "entity_value": "ven-8472"}],
                },
                {"external_id": "invalid-profile", "country": "US"},
            ],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["processed"] == 2
    assert payload["ingested"] == 1
    assert payload["updated"] == 0
    assert payload["invalid"] == 1
    assert payload["profiles_scored"] == 1

    analytics = client.get("/analytics/supply-chain-risk", params={"limit": 10})
    assert analytics.status_code == 200
    rows = analytics.json()
    profile_row = next((row for row in rows if row["profile_id"] == "ven-8472"), None)
    assert profile_row is not None
    assert profile_row["vendor_risk_score"] >= 45.0
    assert len(profile_row["reason_codes"]) > 0

    conn = get_connection()
    source = conn.execute(
        "SELECT source_type, last_status FROM sources WHERE name = ? ORDER BY id DESC LIMIT 1",
        ("Supply Chain Risk (Synthetic TPRM Feed)",),
    ).fetchone()
    conn.close()
    assert source is not None
    assert source["source_type"] == "supply_chain"
    assert source["last_status"] == "ok"


def test_ingest_endpoints_reject_empty_payload_lists(client):
    insider_response = client.post("/ingest/insider-events", json={"events": []})
    assert insider_response.status_code == 422

    supply_response = client.post("/ingest/supply-chain-profiles", json={"profiles": []})
    assert supply_response.status_code == 422


def test_ingest_endpoints_reject_oversized_payload_lists(client):
    oversized_events = [{"subject_id": f"EMP-{idx}"} for idx in range(501)]
    insider_response = client.post(
        "/ingest/insider-events",
        json={"events": oversized_events},
    )
    assert insider_response.status_code == 422

    oversized_profiles = [{"name": f"Vendor {idx}"} for idx in range(501)]
    supply_response = client.post(
        "/ingest/supply-chain-profiles",
        json={"profiles": oversized_profiles},
    )
    assert supply_response.status_code == 422
