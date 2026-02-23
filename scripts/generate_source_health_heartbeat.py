#!/usr/bin/env python3
"""Generate source-health heartbeat artifacts for collector reliability monitoring."""

from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from monitoring.source_health import (
    build_source_health_heartbeat,
    write_source_health_heartbeat_artifacts,
)
from database.init_db import init_db, migrate_schema


def _parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stale-hours",
        type=int,
        default=int(os.getenv("PI_HEARTBEAT_STALE_HOURS", "48")),
        help="Age threshold for stale successful sources (active sources only).",
    )
    parser.add_argument(
        "--watchlist-limit",
        type=int,
        default=12,
        help="Maximum number of at-risk sources to include in the attention table.",
    )
    parser.add_argument(
        "--include-demo",
        action="store_true",
        help="Include demo sources in heartbeat counts.",
    )
    parser.add_argument(
        "--markdown-out",
        default="docs/source_health_heartbeat.md",
        help="Path for latest markdown heartbeat snapshot.",
    )
    parser.add_argument(
        "--jsonl-out",
        default="docs/source_health_heartbeat.jsonl",
        help="Path for append-only JSONL heartbeat log.",
    )
    return parser.parse_args()


def main():
    args = _parse_args()
    init_db()
    migrate_schema()
    snapshot = build_source_health_heartbeat(
        stale_hours=args.stale_hours,
        include_demo=args.include_demo,
        watchlist_limit=args.watchlist_limit,
    )
    markdown_path, jsonl_path = write_source_health_heartbeat_artifacts(
        snapshot,
        markdown_path=args.markdown_out,
        jsonl_path=args.jsonl_out,
    )

    totals = snapshot["totals"]
    print(f"Source health heartbeat written: {markdown_path}")
    print(f"Heartbeat log appended: {jsonl_path}")
    print(
        "Fleet summary: "
        f"sources={totals['sources']} active={totals['active']} "
        f"ok={totals['ok']} error={totals['error']} skipped={totals['skipped']} "
        f"failing={totals['failing']} auto_disabled={totals['auto_disabled']}"
    )


if __name__ == "__main__":
    main()
