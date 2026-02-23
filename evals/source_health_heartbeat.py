"""Source-health heartbeat snapshot helpers."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from analytics.utils import parse_timestamp, utcnow
from database.init_db import get_connection

_KNOWN_STATUSES = {"ok", "error", "skipped", "unknown"}


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _status_key(value):
    status = str(value or "unknown").strip().lower()
    if status in _KNOWN_STATUSES:
        return status
    return "unknown"


def _is_auto_disabled(row):
    if _safe_int(row.get("active"), default=0) != 0:
        return False
    reason = str(row.get("disabled_reason") or "").strip().lower()
    return reason.startswith("auto-disabled")


def _is_stale_success(row, stale_cutoff_dt):
    if _safe_int(row.get("active"), default=0) != 1:
        return False
    success_dt = parse_timestamp(row.get("last_success_at"))
    if success_dt is None:
        return False
    return success_dt < stale_cutoff_dt


def _is_never_succeeded(row):
    if _safe_int(row.get("active"), default=0) != 1:
        return False
    return parse_timestamp(row.get("last_success_at")) is None


def _safe_cell(value):
    raw = str(value or "").replace("\n", " ").replace("\r", " ").strip()
    return raw.replace("|", "/")


def _empty_bucket(source_type):
    return {
        "source_type": source_type,
        "sources": 0,
        "active": 0,
        "ok": 0,
        "error": 0,
        "skipped": 0,
        "unknown": 0,
        "failing": 0,
        "auto_disabled": 0,
        "stale_success": 0,
        "never_succeeded": 0,
        "last_collection_total": 0,
        "avg_latency_ms": None,
        "max_fail_streak": 0,
    }


def _risk_rank(row, stale_cutoff_dt):
    fail_streak = _safe_int(row.get("fail_streak"), default=0)
    status = _status_key(row.get("last_status"))
    active = _safe_int(row.get("active"), default=0)
    stale = _is_stale_success(row, stale_cutoff_dt)
    never_succeeded = _is_never_succeeded(row)
    auto_disabled = _is_auto_disabled(row)
    latency_ms = _safe_float(row.get("last_latency_ms"))
    rank = fail_streak * 10
    if status == "error":
        rank += 12
    if auto_disabled:
        rank += 8
    if stale:
        rank += 6
    if never_succeeded:
        rank += 4
    if active and latency_ms is not None and latency_ms > 5000:
        rank += 2
    return rank


def build_source_health_heartbeat(stale_hours=48, include_demo=False, watchlist_limit=12):
    """Build a source-health heartbeat snapshot."""
    safe_stale_hours = max(1, min(int(stale_hours), 24 * 30))
    safe_watchlist_limit = max(1, min(int(watchlist_limit), 100))
    now_dt = utcnow()
    stale_cutoff_dt = now_dt - timedelta(hours=safe_stale_hours)

    conn = get_connection()
    try:
        query = """SELECT id, name, url, source_type, active,
                          fail_streak, last_status, last_error, last_success_at, last_failure_at,
                          last_collection_count, last_latency_ms, disabled_reason
                   FROM sources
                   WHERE 1=1"""
        params = []
        if not include_demo:
            query += " AND COALESCE(source_type, '') != 'demo'"
        query += " ORDER BY source_type ASC, name ASC"
        rows = [dict(row) for row in conn.execute(query, params).fetchall()]
    finally:
        conn.close()

    buckets = {}
    latency_accum = {}
    watchlist_candidates = []
    totals = _empty_bucket("all")
    totals["source_type"] = "all"

    for row in rows:
        source_type = str(row.get("source_type") or "unknown").strip().lower() or "unknown"
        bucket = buckets.setdefault(source_type, _empty_bucket(source_type))
        status = _status_key(row.get("last_status"))
        fail_streak = _safe_int(row.get("fail_streak"), default=0)
        active = _safe_int(row.get("active"), default=0)
        auto_disabled = _is_auto_disabled(row)
        stale = _is_stale_success(row, stale_cutoff_dt)
        never_succeeded = _is_never_succeeded(row)

        for target in (bucket, totals):
            target["sources"] += 1
            target[status] += 1
            target["active"] += 1 if active else 0
            target["failing"] += 1 if fail_streak > 0 else 0
            target["auto_disabled"] += 1 if auto_disabled else 0
            target["stale_success"] += 1 if stale else 0
            target["never_succeeded"] += 1 if never_succeeded else 0
            target["max_fail_streak"] = max(target["max_fail_streak"], fail_streak)

            collection_count = row.get("last_collection_count")
            if collection_count is not None:
                target["last_collection_total"] += _safe_int(collection_count, default=0)

        latency_ms = _safe_float(row.get("last_latency_ms"))
        if latency_ms is not None:
            for key in (source_type, "all"):
                lat = latency_accum.setdefault(key, {"sum": 0.0, "count": 0})
                lat["sum"] += latency_ms
                lat["count"] += 1

        if _risk_rank(row, stale_cutoff_dt) > 0:
            watchlist_candidates.append(row)

    for key, bucket in list(buckets.items()) + [("all", totals)]:
        lat = latency_accum.get(key)
        if lat and lat["count"] > 0:
            bucket["avg_latency_ms"] = round(lat["sum"] / lat["count"], 2)

    watchlist_candidates.sort(
        key=lambda row: (
            _risk_rank(row, stale_cutoff_dt),
            _safe_int(row.get("fail_streak"), default=0),
            str(row.get("name") or "").lower(),
        ),
        reverse=True,
    )

    watchlist = []
    for row in watchlist_candidates[:safe_watchlist_limit]:
        watchlist.append(
            {
                "id": _safe_int(row.get("id"), default=0),
                "name": row.get("name"),
                "source_type": row.get("source_type"),
                "active": _safe_int(row.get("active"), default=0),
                "fail_streak": _safe_int(row.get("fail_streak"), default=0),
                "last_status": _status_key(row.get("last_status")),
                "last_error": row.get("last_error"),
                "last_success_at": row.get("last_success_at"),
                "last_failure_at": row.get("last_failure_at"),
                "last_collection_count": row.get("last_collection_count"),
                "last_latency_ms": _safe_float(row.get("last_latency_ms")),
                "disabled_reason": row.get("disabled_reason"),
                "stale_success": _is_stale_success(row, stale_cutoff_dt),
                "never_succeeded": _is_never_succeeded(row),
                "auto_disabled": _is_auto_disabled(row),
                "risk_rank": _risk_rank(row, stale_cutoff_dt),
            }
        )

    return {
        "generated_at": now_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "stale_window_hours": safe_stale_hours,
        "include_demo": bool(include_demo),
        "totals": totals,
        "by_collector": [buckets[key] for key in sorted(buckets.keys())],
        "watchlist": watchlist,
    }


def render_source_health_heartbeat_markdown(snapshot):
    """Render heartbeat snapshot as markdown."""
    totals = snapshot["totals"]
    rows = snapshot["by_collector"]
    watchlist = snapshot.get("watchlist") or []
    stale_window_hours = snapshot["stale_window_hours"]
    generated_at = snapshot["generated_at"]

    lines = [
        "# Source Health Heartbeat",
        "",
        f"Generated: {generated_at} UTC",
        f"Stale success threshold: {stale_window_hours}h",
        "",
        "## Fleet Summary",
        f"- Sources: **{totals['sources']}** (active: **{totals['active']}**)",
        (
            f"- Status mix: ok={totals['ok']}, error={totals['error']}, "
            f"skipped={totals['skipped']}, unknown={totals['unknown']}"
        ),
        (
            f"- Risk flags: failing={totals['failing']}, auto-disabled={totals['auto_disabled']}, "
            f"stale-success={totals['stale_success']}, never-succeeded={totals['never_succeeded']}"
        ),
        (
            f"- Throughput telemetry: last_collection_total={totals['last_collection_total']}, "
            f"avg_latency_ms={totals['avg_latency_ms'] if totals['avg_latency_ms'] is not None else 'n/a'}"
        ),
        "",
        "## Collector Status",
        (
            "| Collector | Sources | Active | OK | Error | Skipped | Unknown | "
            "Failing | Auto-Disabled | Stale | Never-Succeeded | Avg Latency (ms) | Last Collection Total |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for row in rows:
        lines.append(
            (
                f"| {_safe_cell(row['source_type'])} | {row['sources']} | {row['active']} | {row['ok']} | "
                f"{row['error']} | {row['skipped']} | {row['unknown']} | {row['failing']} | "
                f"{row['auto_disabled']} | {row['stale_success']} | {row['never_succeeded']} | "
                f"{row['avg_latency_ms'] if row['avg_latency_ms'] is not None else 'n/a'} | "
                f"{row['last_collection_total']} |"
            )
        )

    lines.extend(["", "## Attention Required"])
    if not watchlist:
        lines.append("- None.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            (
                "| Source | Type | Active | Status | Fail Streak | Stale | Never Succeeded | "
                "Last Success | Last Latency (ms) | Last Count | Disabled Reason | Last Error |"
            ),
            "|---|---|---:|---|---:|---:|---:|---|---:|---:|---|---|",
        ]
    )
    for row in watchlist:
        lines.append(
            (
                f"| {_safe_cell(row['name'])} | {_safe_cell(row['source_type'])} | {row['active']} | "
                f"{_safe_cell(row['last_status'])} | {row['fail_streak']} | "
                f"{1 if row['stale_success'] else 0} | {1 if row['never_succeeded'] else 0} | "
                f"{_safe_cell(row['last_success_at']) or 'n/a'} | "
                f"{row['last_latency_ms'] if row['last_latency_ms'] is not None else 'n/a'} | "
                f"{row['last_collection_count'] if row['last_collection_count'] is not None else 'n/a'} | "
                f"{_safe_cell(row['disabled_reason']) or 'n/a'} | "
                f"{_safe_cell(row['last_error']) or 'n/a'} |"
            )
        )
    return "\n".join(lines) + "\n"


def write_source_health_heartbeat_artifacts(snapshot, markdown_path, jsonl_path):
    """Write heartbeat artifacts to markdown and jsonl outputs."""
    markdown_target = Path(markdown_path)
    jsonl_target = Path(jsonl_path)
    markdown_target.parent.mkdir(parents=True, exist_ok=True)
    jsonl_target.parent.mkdir(parents=True, exist_ok=True)

    markdown_target.write_text(
        render_source_health_heartbeat_markdown(snapshot),
        encoding="utf-8",
    )
    with jsonl_target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(snapshot, sort_keys=True) + "\n")
    return markdown_target, jsonl_target
