"""Dark-web collector scaffold.

This module intentionally ships in disabled mode. It provides a stable
integration point in the scraper pipeline while policy/legal review and source
validation are completed.
"""

import os

from database.init_db import get_connection
from scraper.source_health import mark_source_failure, mark_source_skipped


def _enabled():
    return os.getenv("PI_ENABLE_DARKWEB_COLLECTOR", "0").lower() in {"1", "true", "yes"}


def run_darkweb_collector(frequency_snapshot=None):
    """Placeholder collector for future dark-web integrations.

    Returns:
        int: Number of new alerts ingested (always 0 in scaffold mode).
    """
    # Keep function signature aligned with other collectors.
    _ = frequency_snapshot

    conn = get_connection()
    try:
        source_rows = conn.execute(
            "SELECT id FROM sources WHERE source_type = 'darkweb'"
        ).fetchall()
        source_ids = [row["id"] for row in source_rows]

        if not _enabled():
            for source_id in source_ids:
                mark_source_skipped(conn, source_id, "PI_ENABLE_DARKWEB_COLLECTOR not set")
            conn.commit()
            print("Dark-web collector skipped (PI_ENABLE_DARKWEB_COLLECTOR not set).")
            return 0

        for source_id in source_ids:
            mark_source_failure(
                conn,
                source_id,
                "collector enabled but implementation not available",
            )
        conn.commit()
    finally:
        conn.close()

    print(
        "Dark-web collector is enabled but not implemented. "
        "Complete legal/ToS review and connector hardening before activation."
    )
    return 0
