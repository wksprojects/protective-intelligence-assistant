from datetime import timedelta

from analytics.utils import utcnow
from database.init_db import get_connection
from monitoring.source_health import (
    build_source_health_heartbeat,
    render_source_health_heartbeat_markdown,
    write_source_health_heartbeat_artifacts,
)


def test_source_health_heartbeat_snapshot_and_markdown(client):
    conn = get_connection()
    sources = conn.execute("SELECT id, source_type FROM sources ORDER BY id LIMIT 3").fetchall()
    assert len(sources) == 3
    source_ids = [int(row["id"]) for row in sources]

    conn.execute(
        """UPDATE sources
        SET last_status = 'unknown',
            fail_streak = 0,
            active = 1,
            last_error = NULL,
            last_success_at = NULL,
            last_failure_at = NULL,
            last_collection_count = NULL,
            last_latency_ms = NULL,
            disabled_reason = NULL"""
    )

    now = utcnow()
    recent_success = (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    stale_success = (now - timedelta(hours=72)).strftime("%Y-%m-%d %H:%M:%S")
    recent_failure = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")

    conn.execute(
        """UPDATE sources
        SET last_status = 'ok',
            last_success_at = ?,
            last_collection_count = 7,
            last_latency_ms = 123.4
        WHERE id = ?""",
        (recent_success, source_ids[0]),
    )
    conn.execute(
        """UPDATE sources
        SET last_status = 'error',
            fail_streak = 3,
            last_error = 'timeout',
            last_failure_at = ?,
            last_success_at = ?,
            last_collection_count = 0,
            last_latency_ms = 6500.0
        WHERE id = ?""",
        (recent_failure, stale_success, source_ids[1]),
    )
    conn.execute(
        """UPDATE sources
        SET active = 0,
            last_status = 'error',
            fail_streak = 5,
            disabled_reason = 'auto-disabled after 5 consecutive failures',
            last_failure_at = ?,
            last_success_at = ?,
            last_collection_count = 0,
            last_latency_ms = 50.0
        WHERE id = ?""",
        (recent_failure, stale_success, source_ids[2]),
    )
    conn.commit()
    conn.close()

    snapshot = build_source_health_heartbeat(stale_hours=24, include_demo=True, watchlist_limit=20)
    totals = snapshot["totals"]

    assert totals["sources"] >= 3
    assert totals["ok"] >= 1
    assert totals["error"] >= 2
    assert totals["failing"] >= 2
    assert totals["auto_disabled"] >= 1
    assert totals["stale_success"] >= 1
    assert totals["last_collection_total"] >= 7
    assert snapshot["watchlist"]

    markdown = render_source_health_heartbeat_markdown(snapshot)
    assert "# Source Health Heartbeat" in markdown
    assert "| Collector | Sources | Active | OK | Error |" in markdown
    assert "## Attention Required" in markdown


def test_source_health_heartbeat_artifact_writer(client, tmp_path):
    snapshot = build_source_health_heartbeat(stale_hours=48, include_demo=True, watchlist_limit=5)
    md_path = tmp_path / "heartbeat.md"
    jsonl_path = tmp_path / "heartbeat.jsonl"
    write_source_health_heartbeat_artifacts(
        snapshot,
        markdown_path=md_path,
        jsonl_path=jsonl_path,
    )

    assert md_path.exists()
    assert jsonl_path.exists()
    assert "Source Health Heartbeat" in md_path.read_text(encoding="utf-8")
    assert len(jsonl_path.read_text(encoding="utf-8").strip().splitlines()) == 1
