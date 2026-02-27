"""Demo artifact generator for EP workflow showcase."""

import json
from pathlib import Path

from analytics.entity_extraction import extract_and_store_alert_entities
from analytics.ep_pipeline import process_ep_signals
from analytics.intelligence_report import generate_daily_report
from analytics.risk_scoring import increment_keyword_frequency, score_alert
from analytics.travel_brief import generate_travel_brief
from analytics.utils import utcnow
from database.init_db import get_connection

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "demo_alerts.json"
DOCS_DIR = Path(__file__).resolve().parents[1] / "docs"


def _load_fixtures():
    if FIXTURE_PATH.exists():
        return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return []


def _ensure_source(conn, name, url):
    row = conn.execute("SELECT id FROM sources WHERE url = ?", (url,)).fetchone()
    if row:
        conn.execute(
            "UPDATE sources SET name = ?, source_type = 'demo', active = 0 WHERE id = ?",
            (name, row["id"]),
        )
        return row["id"]
    conn.execute(
        """INSERT INTO sources (name, url, source_type, credibility_score, active)
        VALUES (?, ?, ?, ?, 0)""",
        (name, url, "demo", 0.8),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _ensure_keyword(conn, keyword):
    term = keyword["term"]
    row = conn.execute("SELECT id FROM keywords WHERE term = ?", (term,)).fetchone()
    if row:
        conn.execute(
            "UPDATE keywords SET category = ?, weight = ? WHERE id = ?",
            (keyword.get("category", "protective_intel"), float(keyword.get("weight", 1.0)), row["id"]),
        )
        return row["id"]
    conn.execute(
        "INSERT INTO keywords (term, category, weight, active) VALUES (?, ?, ?, 1)",
        (term, keyword.get("category", "protective_intel"), float(keyword.get("weight", 1.0))),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _ensure_demo_svgs():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    protectee_svg = DOCS_DIR / "protectee_view.svg"
    map_svg = DOCS_DIR / "map_view.svg"
    if not protectee_svg.exists():
        protectee_svg.write_text(
            """<svg xmlns='http://www.w3.org/2000/svg' width='960' height='540'>
<rect width='960' height='540' fill='#0f172a'/>
<text x='32' y='56' fill='#f8fafc' font-size='32' font-family='Arial'>Protectee View (Demo)</text>
<text x='32' y='110' fill='#cbd5e1' font-size='20' font-family='Arial'>Jane Doe | TAS 78 | Fixation + Leakage</text>
<text x='32' y='150' fill='#cbd5e1' font-size='18' font-family='Arial'>Recent hits: 6 across 4 days</text>
<text x='32' y='190' fill='#cbd5e1' font-size='18' font-family='Arial'>Top evidence: "death threat ... tomorrow at 7pm"</text>
</svg>""",
            encoding="utf-8",
        )
    if not map_svg.exists():
        map_svg.write_text(
            """<svg xmlns='http://www.w3.org/2000/svg' width='960' height='540'>
<rect width='960' height='540' fill='#111827'/>
<text x='32' y='56' fill='#f9fafb' font-size='32' font-family='Arial'>Map View (Demo)</text>
<circle cx='240' cy='240' r='22' fill='#10b981'/><text x='280' y='247' fill='#e5e7eb' font-size='18'>Acme HQ</text>
<circle cx='520' cy='300' r='16' fill='#f97316'/><text x='560' y='307' fill='#e5e7eb' font-size='18'>Protest Alert</text>
<circle cx='680' cy='180' r='16' fill='#ef4444'/><text x='720' y='187' fill='#e5e7eb' font-size='18'>Threat Alert</text>
</svg>""",
            encoding="utf-8",
        )


def run_demo_pack():
    fixtures = _load_fixtures()
    if not fixtures:
        raise RuntimeError("Demo fixtures missing: fixtures/demo_alerts.json")

    conn = get_connection()
    inserted = 0
    try:
        for item in fixtures:
            source_id = _ensure_source(conn, item["source_name"], item["source_url"])
            keyword_id = _ensure_keyword(conn, item["keyword"])

            exists = conn.execute(
                "SELECT id FROM alerts WHERE url = ? AND source_id = ? AND keyword_id = ?",
                (item["url"], source_id, keyword_id),
            ).fetchone()
            if exists:
                continue

            conn.execute(
                """INSERT INTO alerts
                (source_id, keyword_id, title, content, url, matched_term,
                 published_at, severity, duplicate_of)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'low', NULL)""",
                (
                    source_id,
                    keyword_id,
                    item["title"],
                    item["content"][:2000],
                    item["url"],
                    item["keyword"]["term"],
                    item.get("published_at") or utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
            alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            baseline = score_alert(conn, alert_id, keyword_id, source_id)
            extract_and_store_alert_entities(conn, alert_id, f"{item['title']}\n{item['content']}")
            process_ep_signals(
                conn,
                alert_id=alert_id,
                title=item["title"],
                content=item["content"],
                keyword_category=item["keyword"].get("category"),
                baseline_score=baseline,
            )
            increment_keyword_frequency(conn, keyword_id)
            inserted += 1

        conn.commit()
    finally:
        conn.close()

    generate_daily_report(report_date=utcnow().strftime("%Y-%m-%d"))
    conn = get_connection()
    demo_rows = conn.execute(
        """SELECT a.id, a.title, a.ors_score, a.tas_score, a.severity
        FROM alerts a
        JOIN sources s ON s.id = a.source_id
        WHERE s.source_type = 'demo'
        ORDER BY COALESCE(a.ors_score, a.risk_score) DESC, a.tas_score DESC, a.id DESC""",
    ).fetchall()
    poi_rows = conn.execute(
        """SELECT p.name, pa.tas_score
        FROM poi_assessments pa
        JOIN pois p ON p.id = pa.poi_id
        ORDER BY pa.created_at DESC
        LIMIT 5""",
    ).fetchall()
    conn.close()

    brief = generate_travel_brief(
        destination="San Francisco, CA",
        start_dt=utcnow().strftime("%Y-%m-%d"),
        end_dt=(utcnow()).strftime("%Y-%m-%d"),
        persist=True,
    )

    report_lines = ["# Demo Daily Report", "", "## Operational Escalations (ORS)"]
    if demo_rows:
        for row in demo_rows[:10]:
            report_lines.append(
                f"- [#{row['id']}] ORS={float(row['ors_score'] or 0):.1f} "
                f"TAS={float(row['tas_score'] or 0):.1f} | {row['severity']} | {row['title']}"
            )
    else:
        report_lines.append("- No demo alerts available.")

    report_lines.append("")
    report_lines.append("## Protectee Escalations (TAS)")
    if poi_rows:
        for row in poi_rows:
            report_lines.append(f"- {row['name']}: TAS={float(row['tas_score'] or 0):.1f}")
    else:
        report_lines.append("- No protectee assessments generated.")

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "demo_daily_report.md").write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )
    (DOCS_DIR / "demo_travel_brief.md").write_text(
        brief["content_md"],
        encoding="utf-8",
    )
    _ensure_demo_svgs()

    return {
        "inserted_alerts": inserted,
        "report_path": str(DOCS_DIR / "demo_daily_report.md"),
        "brief_path": str(DOCS_DIR / "demo_travel_brief.md"),
    }
