"""
Protective Intelligence Assistant - Entry Point

Usage:
    python run.py init        Initialize DB and seed from config/watchlist.yaml (fallback defaults)
    python run.py sync        Sync watchlist-driven defaults into existing DB
    python run.py scrape      Run all scrapers
    python run.py api         Start FastAPI server
    python run.py dashboard   Start Streamlit dashboard
    python run.py purge       Purge raw content older than retention window
    python run.py purge-demo  Remove demo-seeded content from database
    python run.py evaluate    Generate quantitative evaluation memo
    python run.py demo        Load fixtures and generate demo EP artifacts
    python run.py all         Start API + Dashboard (requires separate terminal for each)
"""

import subprocess
import sys

from database.init_db import (
    get_connection,
    init_db,
    migrate_schema,
    purge_raw_content,
    seed_default_events,
    seed_default_keywords,
    seed_default_pois,
    seed_default_protected_locations,
    seed_default_sources,
    seed_threat_actors,
)
from scraper import run_all_scrapers


def purge_demo_content():
    conn = get_connection()
    try:
        deleted_alerts = conn.execute(
            """DELETE FROM alerts
            WHERE source_id IN (
                SELECT id FROM sources
                WHERE source_type = 'demo'
                   OR LOWER(name) LIKE 'demo %'
                   OR url LIKE 'https://example.org/demo-%'
            )"""
        ).rowcount
        deleted_sources = conn.execute(
            """DELETE FROM sources
            WHERE source_type = 'demo'
               OR LOWER(name) LIKE 'demo %'
               OR url LIKE 'https://example.org/demo-%'"""
        ).rowcount

        # Rebuild keyword frequency to remove demo-only spike artifacts.
        conn.execute("DELETE FROM keyword_frequency")
        conn.execute(
            """INSERT INTO keyword_frequency (keyword_id, date, count)
            SELECT a.keyword_id,
                   date(COALESCE(a.published_at, a.created_at)) AS freq_date,
                   COUNT(*) AS cnt
            FROM alerts a
            LEFT JOIN sources s ON s.id = a.source_id
            WHERE a.keyword_id IS NOT NULL
              AND a.duplicate_of IS NULL
              AND COALESCE(s.source_type, '') != 'demo'
            GROUP BY a.keyword_id, date(COALESCE(a.published_at, a.created_at))"""
        )

        deleted_reports = conn.execute("DELETE FROM intelligence_reports").rowcount
        conn.commit()
    finally:
        conn.close()

    print(
        "Demo purge complete:"
        f" alerts={max(deleted_alerts or 0, 0)}"
        f" sources={max(deleted_sources or 0, 0)}"
        f" reports={max(deleted_reports or 0, 0)}"
    )


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    command = sys.argv[1].lower()

    if command == "init":
        init_db()
        migrate_schema()
        conn = get_connection()
        source_count = conn.execute("SELECT COUNT(*) AS count FROM sources").fetchone()["count"]
        keyword_count = conn.execute("SELECT COUNT(*) AS count FROM keywords").fetchone()["count"]
        actor_count = conn.execute("SELECT COUNT(*) AS count FROM threat_actors").fetchone()["count"]
        poi_count = conn.execute("SELECT COUNT(*) AS count FROM pois").fetchone()["count"]
        loc_count = conn.execute("SELECT COUNT(*) AS count FROM protected_locations").fetchone()["count"]
        event_count = conn.execute("SELECT COUNT(*) AS count FROM events").fetchone()["count"]
        conn.close()

        if source_count == 0:
            seed_default_sources()
        if keyword_count == 0:
            seed_default_keywords()
        if poi_count == 0:
            seed_default_pois()
        if loc_count == 0:
            seed_default_protected_locations()
        if event_count == 0:
            seed_default_events()
        if actor_count == 0:
            seed_threat_actors()

    elif command == "sync":
        init_db()
        migrate_schema()
        seed_default_sources()
        seed_default_keywords()
        seed_default_pois()
        seed_default_protected_locations()
        seed_default_events()
        seed_threat_actors()

    elif command == "scrape":
        init_db()
        migrate_schema()
        run_all_scrapers()

    elif command == "api":
        init_db()
        migrate_schema()
        subprocess.run(
            ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
        )

    elif command == "dashboard":
        subprocess.run(["streamlit", "run", "dashboard/app.py", "--server.port", "8501"])

    elif command == "purge":
        init_db()
        migrate_schema()
        purge_raw_content()

    elif command in ("purge-demo", "purge_demo"):
        init_db()
        migrate_schema()
        purge_demo_content()

    elif command == "evaluate":
        subprocess.run([sys.executable, "scripts/generate_evaluation_memo.py"], check=True)

    elif command == "demo":
        from analytics.demo_pack import run_demo_pack

        init_db()
        migrate_schema()
        seed_default_sources()
        seed_default_keywords()
        seed_default_pois()
        seed_default_protected_locations()
        seed_default_events()
        seed_threat_actors()
        result = run_demo_pack()
        print("Demo artifacts generated:")
        print(f"  - {result['report_path']}")
        print(f"  - {result['brief_path']}")

    elif command == "all":
        print("Run in separate terminals:")
        print("  Terminal 1: python run.py api")
        print("  Terminal 2: python run.py dashboard")
        print("\nOr use: docker compose up")

    else:
        print(f"Unknown command: {command}")
        print(__doc__)


if __name__ == "__main__":
    main()
