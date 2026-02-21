from analytics.entity_extraction import extract_and_store_alert_entities
from analytics.ep_pipeline import process_ep_signals
from analytics.risk_scoring import score_alert
from database.init_db import get_connection


def test_pois_endpoint_returns_seeded_items(client):
    response = client.get("/pois")
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, list)
    assert len(payload) >= 1
    assert "name" in payload[0]


def test_alert_score_includes_ors_and_tas(client):
    conn = get_connection()
    source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    keyword_id = conn.execute(
        "SELECT id FROM keywords WHERE category = 'protective_intel' ORDER BY id LIMIT 1"
    ).fetchone()["id"]

    conn.execute(
        """INSERT INTO alerts
        (source_id, keyword_id, title, content, url, matched_term, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            source_id,
            keyword_id,
            "Threat to CEO near Apple Park",
            "A death threat to CEO was posted near Apple Park in Cupertino, CA tomorrow.",
            "https://example.com/ep-score",
            "threat to CEO",
            "low",
        ),
    )
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    baseline = score_alert(conn, alert_id, keyword_id, source_id, frequency_override=1.2, z_score_override=0.1)
    extract_and_store_alert_entities(
        conn,
        alert_id,
        "Threat to CEO near Apple Park in Cupertino, CA tomorrow",
    )
    process_ep_signals(
        conn,
        alert_id=alert_id,
        title="Threat to CEO near Apple Park",
        content="A death threat to CEO was posted near Apple Park in Cupertino, CA tomorrow.",
        keyword_category="protective_intel",
        baseline_score=baseline,
    )
    conn.commit()
    conn.close()

    response = client.get(f"/alerts/{alert_id}/score", params={"uncertainty": 1, "n": 300})
    assert response.status_code == 200
    payload = response.json()
    assert payload["ors_score"] is not None
    assert payload["tas_score"] is not None
    assert payload["uncertainty"]["p95"] is not None


def test_travel_brief_endpoint_returns_markdown(client):
    response = client.post(
        "/briefs/travel",
        json={
            "destination": "San Francisco, CA",
            "start_dt": "2026-02-21",
            "end_dt": "2026-02-24",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert "content_md" in payload
    assert "Travel Brief" in payload["content_md"]
