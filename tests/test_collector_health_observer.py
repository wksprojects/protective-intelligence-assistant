import pytest

from database.init_db import get_connection
from monitoring.collector_health import CollectorHealthObserver


def test_collector_health_observer_marks_success(client):
    conn = get_connection()
    source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    observer = CollectorHealthObserver(conn, "observer-test")

    with observer.observe(source_id, collection_count=lambda: 5):
        pass

    row = conn.execute(
        """SELECT fail_streak, last_status, last_collection_count, last_latency_ms, last_success_at
        FROM sources WHERE id = ?""",
        (source_id,),
    ).fetchone()
    conn.commit()
    conn.close()

    assert row["fail_streak"] == 0
    assert row["last_status"] == "ok"
    assert row["last_collection_count"] == 5
    assert row["last_latency_ms"] is not None
    assert row["last_success_at"] is not None


def test_collector_health_observer_marks_failure(client):
    conn = get_connection()
    source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    observer = CollectorHealthObserver(conn, "observer-test")

    with pytest.raises(RuntimeError):
        with observer.observe(source_id, collection_count=0):
            raise RuntimeError("observer boom")

    row = conn.execute(
        "SELECT fail_streak, last_status, last_error FROM sources WHERE id = ?",
        (source_id,),
    ).fetchone()
    conn.commit()
    conn.close()

    assert row["fail_streak"] >= 1
    assert row["last_status"] == "error"
    assert "observer boom" in (row["last_error"] or "")
