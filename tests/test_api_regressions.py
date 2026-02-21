from datetime import datetime, timedelta

from database.init_db import get_connection


def _count_evaluation_rows():
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) as count FROM evaluation_metrics").fetchone()["count"]
    conn.close()
    return count


def test_evaluation_unknown_source_returns_404(client):
    response = client.get("/analytics/evaluation", params={"source_id": 999999})
    assert response.status_code == 404
    assert response.json()["detail"] == "Source not found"


def test_evaluation_endpoint_is_side_effect_free(client):
    before = _count_evaluation_rows()

    first = client.get("/analytics/evaluation")
    assert first.status_code == 200
    assert isinstance(first.json(), list)

    after_first = _count_evaluation_rows()
    assert after_first == before

    second = client.get("/analytics/evaluation")
    assert second.status_code == 200

    after_second = _count_evaluation_rows()
    assert after_second == before


def test_daily_report_rejects_invalid_date(client):
    response = client.get("/intelligence/daily", params={"date": "2026-13-99"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid date format. Use YYYY-MM-DD."


def test_spikes_endpoint_rejects_invalid_date(client):
    response = client.get("/analytics/spikes", params={"date": "not-a-date"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid date format. Use YYYY-MM-DD."


def test_health_and_ready_endpoints(client):
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert "uptime_seconds" in health.json()

    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"


def test_metrics_endpoint_shape(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    payload = response.json()
    for key in (
        "uptime_seconds",
        "alerts_total",
        "alerts_unreviewed",
        "scrape_runs_total",
        "audit_error_events",
    ):
        assert key in payload


def test_backtest_endpoint_dashboard_payload(client):
    response = client.get("/analytics/backtest")
    assert response.status_code == 200
    payload = response.json()
    assert "cases" in payload
    assert "naive_accuracy" in payload
    assert "multifactor_accuracy" in payload
    assert "improvement" in payload
    assert isinstance(payload["cases"], list)


def test_travel_brief_rejects_reversed_dates(client):
    response = client.post(
        "/briefs/travel",
        json={
            "destination": "San Francisco, CA",
            "start_dt": "2026-02-24",
            "end_dt": "2026-02-21",
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "end_dt must be on or after start_dt"


def test_daily_report_uses_requested_date_for_spike_detection(client):
    report_dt = datetime(2025, 1, 10)
    report_date = report_dt.strftime("%Y-%m-%d")

    conn = get_connection()
    keyword_id = conn.execute("SELECT id FROM keywords WHERE term = 'stalking'").fetchone()["id"]

    for days_back in range(1, 8):
        day = (report_dt - timedelta(days=days_back)).strftime("%Y-%m-%d")
        conn.execute(
            "INSERT INTO keyword_frequency (keyword_id, date, count) VALUES (?, ?, ?)",
            (keyword_id, day, 1),
        )

    conn.execute(
        "INSERT INTO keyword_frequency (keyword_id, date, count) VALUES (?, ?, ?)",
        (keyword_id, report_date, 10),
    )
    conn.commit()
    conn.close()

    response = client.get("/intelligence/daily", params={"date": report_date})
    assert response.status_code == 200

    report = response.json()
    ransomware_theme = next(
        (theme for theme in report["emerging_themes"] if theme["term"] == "stalking"),
        None,
    )
    assert ransomware_theme is not None
    assert ransomware_theme["today_count"] == 10
