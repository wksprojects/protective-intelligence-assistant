"""Per-source scrape health tracking.

Tracks consecutive failures and supports automatic source disabling for
consistently failing feeds.
"""

import os

from analytics.utils import utcnow


def _truthy(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _failure_threshold():
    try:
        return max(1, int(os.getenv("PI_SOURCE_FAIL_DISABLE_THRESHOLD", "5")))
    except (TypeError, ValueError):
        return 5


def _auto_disable_enabled():
    return _truthy(os.getenv("PI_SOURCE_AUTO_DISABLE", "1"))


def _safe_error(error_message, max_len=400):
    if error_message is None:
        return None
    value = str(error_message).strip()
    if not value:
        return None
    return value[:max_len]


def mark_source_success(conn, source_id):
    if source_id is None:
        return
    conn.execute(
        """UPDATE sources
        SET fail_streak = 0,
            last_status = 'ok',
            last_error = NULL,
            disabled_reason = NULL,
            active = 1,
            last_success_at = ?
        WHERE id = ?""",
        (utcnow().strftime("%Y-%m-%d %H:%M:%S"), int(source_id)),
    )


def mark_source_failure(conn, source_id, error_message):
    if source_id is None:
        return
    row = conn.execute(
        "SELECT fail_streak, active FROM sources WHERE id = ?",
        (int(source_id),),
    ).fetchone()
    if not row:
        return

    next_fail_streak = int(row["fail_streak"] or 0) + 1
    now = utcnow().strftime("%Y-%m-%d %H:%M:%S")
    last_error = _safe_error(error_message)

    disable_now = _auto_disable_enabled() and next_fail_streak >= _failure_threshold()
    disabled_reason = None
    if disable_now:
        disabled_reason = (
            f"auto-disabled after {next_fail_streak} consecutive failures at {now}"
        )

    conn.execute(
        """UPDATE sources
        SET fail_streak = ?,
            last_status = 'error',
            last_error = ?,
            last_failure_at = ?,
            active = CASE WHEN ? THEN 0 ELSE active END,
            disabled_reason = CASE WHEN ? THEN ? ELSE disabled_reason END
        WHERE id = ?""",
        (
            next_fail_streak,
            last_error,
            now,
            1 if disable_now else 0,
            1 if disable_now else 0,
            disabled_reason,
            int(source_id),
        ),
    )


def mark_source_skipped(conn, source_id, reason=None):
    if source_id is None:
        return
    conn.execute(
        """UPDATE sources
        SET last_status = 'skipped',
            last_error = COALESCE(?, last_error)
        WHERE id = ?""",
        (_safe_error(reason), int(source_id)),
    )
