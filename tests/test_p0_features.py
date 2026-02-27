import math
from datetime import timedelta

from analytics.entity_extraction import extract_and_store_alert_entities
from analytics.utils import utcnow
from analytics.extraction import extract, extract_and_store_alert_artifacts
from analytics.risk_scoring import score_alert
from analytics.uncertainty import score_distribution
from database.init_db import get_connection


def _insert_alert(source_id, keyword_id, title, content, url, risk_score=90.0):
    conn = get_connection()
    conn.execute(
        """INSERT INTO alerts
        (source_id, keyword_id, title, content, url, matched_term, severity, risk_score, published_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            source_id,
            keyword_id,
            title,
            content,
            url,
            "stalking",
            "high",
            risk_score,
            utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    conn.close()
    return alert_id


def test_extraction_regex_fallback_finds_cve(monkeypatch):
    import analytics.extraction as extraction

    monkeypatch.setattr(extraction, "_SPACY_ATTEMPTED", True)
    monkeypatch.setattr(extraction, "_SPACY_NLP", None)

    result = extract("Observed exploitation of CVE-2026-12345 from 1.2.3.4.")
    cves = [ioc["value"] for ioc in result["iocs"] if ioc["type"] == "cve"]
    assert "CVE-2026-12345" in cves
    assert result["meta"]["extractor_used"] == "regex"


def test_ioc_endpoint_and_daily_report_include_cve(client):
    conn = get_connection()
    source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    keyword_id = conn.execute("SELECT id FROM keywords WHERE term = 'stalking'").fetchone()["id"]
    conn.close()

    alert_id = _insert_alert(
        source_id=source_id,
        keyword_id=keyword_id,
        title="CVE exploit seen",
        content="Analysts observed CVE-2026-42424 exploitation.",
        url="https://example.com/cve-seen",
        risk_score=92.0,
    )

    conn = get_connection()
    extract_and_store_alert_artifacts(
        conn,
        alert_id,
        "CVE exploit seen\nAnalysts observed CVE-2026-42424 exploitation.",
    )
    conn.commit()
    conn.close()

    ioc_resp = client.get(f"/alerts/{alert_id}/iocs")
    assert ioc_resp.status_code == 200
    ioc_values = [ioc["value"] for ioc in ioc_resp.json() if ioc["type"] == "cve"]
    assert "CVE-2026-42424" in ioc_values

    today = utcnow().strftime("%Y-%m-%d")
    report_resp = client.get("/intelligence/daily", params={"date": today})
    assert report_resp.status_code == 200
    assert "CVE-2026-42424" in report_resp.json().get("new_cves", [])


def test_entities_endpoint_returns_regex_extracted_iocs(client):
    conn = get_connection()
    source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    keyword_id = conn.execute("SELECT id FROM keywords WHERE term = 'stalking'").fetchone()["id"]
    conn.close()

    alert_id = _insert_alert(
        source_id=source_id,
        keyword_id=keyword_id,
        title="Entity endpoint seed",
        content="IOC sweep: CVE-2026-10101 from 8.8.8.8 and https://example.com/path",
        url="https://example.com/entities",
        risk_score=88.0,
    )

    conn = get_connection()
    extract_and_store_alert_entities(
        conn,
        alert_id,
        "Entity endpoint seed IOC sweep: CVE-2026-10101 from 8.8.8.8 and https://example.com/path",
    )
    conn.commit()
    conn.close()

    response = client.get(f"/alerts/{alert_id}/entities")
    assert response.status_code == 200
    payload = response.json()
    pairs = {(item["entity_type"], item["entity_value"]) for item in payload}
    assert ("cve", "CVE-2026-10101") in pairs
    assert ("ipv4", "8.8.8.8") in pairs
    assert ("url", "https://example.com/path") in pairs


def test_uncertainty_interval_width_shrinks_with_more_evidence():
    broad = score_distribution(
        keyword_weight=4.0,
        keyword_sigma=0.8,
        freq_factor=2.0,
        recency_factor=0.9,
        alpha=2,
        beta=2,
        n=1200,
        seed=7,
    )
    narrow = score_distribution(
        keyword_weight=4.0,
        keyword_sigma=0.8,
        freq_factor=2.0,
        recency_factor=0.9,
        alpha=30,
        beta=5,
        n=1200,
        seed=7,
    )
    assert (broad["p95"] - broad["p05"]) > (narrow["p95"] - narrow["p05"])


def test_score_endpoint_uncertainty_works_without_weight_sigma(client):
    conn = get_connection()
    source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    keyword_id = conn.execute("SELECT id FROM keywords WHERE term = 'stalking'").fetchone()["id"]
    conn.execute("UPDATE keywords SET weight_sigma = NULL WHERE id = ?", (keyword_id,))
    conn.execute(
        """INSERT INTO alerts
        (source_id, keyword_id, title, content, url, matched_term, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            source_id,
            keyword_id,
            "Uncertainty check alert",
            "content",
            "https://example.com/uncertainty",
            "stalking",
            "low",
        ),
    )
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    score_alert(conn, alert_id, keyword_id, source_id, frequency_override=1.2, z_score_override=0.1)
    conn.commit()
    conn.close()

    response = client.get(f"/alerts/{alert_id}/score", params={"uncertainty": 1, "n": 300})
    assert response.status_code == 200
    payload = response.json()
    assert "mc_mean" not in payload
    assert "mc_p05" not in payload
    assert "mc_p95" not in payload
    assert "mc_std" not in payload
    assert "uncertainty" in payload
    assert payload["uncertainty"]["n"] == 300
    assert payload["uncertainty"]["mean"] is not None
    assert payload["uncertainty"]["p05"] is not None
    assert payload["uncertainty"]["p95"] is not None
    assert payload["uncertainty"]["std"] is not None


def test_forecast_fallback_and_ewma_modes(client):
    conn = get_connection()
    keyword_id = conn.execute("SELECT id FROM keywords WHERE term = 'stalking'").fetchone()["id"]
    start = utcnow() - timedelta(days=30)

    # Sparse history first -> naive fallback.
    for i in range(10):
        day = (start + timedelta(days=i)).strftime("%Y-%m-%d")
        conn.execute(
            "INSERT INTO keyword_frequency (keyword_id, date, count) VALUES (?, ?, ?)",
            (keyword_id, day, 2 + (i % 2)),
        )
    conn.commit()

    naive_resp = client.get(f"/analytics/forecast/keyword/{keyword_id}", params={"horizon": 7})
    assert naive_resp.status_code == 200
    naive_payload = naive_resp.json()
    assert naive_payload["forecast"][0]["method"] == "naive_last_value"

    # Extend to enough history -> ewma_trend with finite SMAPE.
    for i in range(10, 28):
        day = (start + timedelta(days=i)).strftime("%Y-%m-%d")
        conn.execute(
            "INSERT INTO keyword_frequency (keyword_id, date, count) VALUES (?, ?, ?)",
            (keyword_id, day, 5 + (i % 4)),
        )
    conn.commit()
    conn.close()

    ewma_resp = client.get(f"/analytics/forecast/keyword/{keyword_id}", params={"horizon": 7})
    assert ewma_resp.status_code == 200
    ewma_payload = ewma_resp.json()
    assert ewma_payload["forecast"][0]["method"] == "ewma_trend"
    assert ewma_payload["quality"]["smape"] is not None
    assert math.isfinite(ewma_payload["quality"]["smape"])


def test_graph_endpoint_returns_nodes_and_edges(client):
    conn = get_connection()
    source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    keyword_id = conn.execute("SELECT id FROM keywords WHERE term = 'stalking'").fetchone()["id"]
    conn.close()

    alert_id = _insert_alert(
        source_id=source_id,
        keyword_id=keyword_id,
        title="Graph seed alert",
        content="Acme observed CVE-2026-99999 from 8.8.8.8",
        url="https://example.com/graph-seed",
        risk_score=96.0,
    )
    conn = get_connection()
    extract_and_store_alert_artifacts(
        conn,
        alert_id,
        "Graph seed alert\nAcme observed CVE-2026-99999 from 8.8.8.8",
    )
    conn.commit()
    conn.close()

    response = client.get(
        "/analytics/graph",
        params={"days": 1, "min_score": 90, "limit_alerts": 500},
    )
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["nodes"]) > 0
    assert len(payload["edges"]) > 0
