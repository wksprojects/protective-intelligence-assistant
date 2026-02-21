"""Travel brief generator for EP workflows."""

from datetime import datetime
from math import asin, cos, radians, sin, sqrt

from analytics.governance import redact_text
from analytics.location_enrichment import geocode_query
from database.init_db import get_connection


def _haversine_miles(lat1, lon1, lat2, lon2):
    r = 3958.756
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    return r * c


def _as_dt(value):
    return datetime.strptime(value, "%Y-%m-%d") if len(value) == 10 else datetime.fromisoformat(value)


def generate_travel_brief(
    destination,
    start_dt,
    end_dt,
    poi_id=None,
    protected_location_id=None,
    include_demo=False,
    persist=True,
):
    conn = get_connection()
    try:
        start_value = _as_dt(start_dt).strftime("%Y-%m-%d 00:00:00")
        end_value = _as_dt(end_dt).strftime("%Y-%m-%d 23:59:59")

        coords = geocode_query(conn, destination)
        internal = []

        demo_filter = ""
        if not include_demo:
            demo_filter = " AND COALESCE(s.source_type, '') != 'demo'"

        alerts = conn.execute(
            f"""SELECT a.id, a.title, a.content, a.ors_score, a.tas_score,
                      COALESCE(a.published_at, a.created_at) AS ts,
                      s.name AS source_name,
                      al.location_text, al.lat, al.lon
            FROM alerts a
            LEFT JOIN sources s ON s.id = a.source_id
            LEFT JOIN alert_locations al ON al.alert_id = a.id
            WHERE datetime(COALESCE(a.published_at, a.created_at)) >= datetime(?)
              AND datetime(COALESCE(a.published_at, a.created_at)) <= datetime(?)
              AND a.duplicate_of IS NULL
              {demo_filter}""",
            (start_value, end_value),
        ).fetchall()

        for row in alerts:
            distance = None
            if coords and row["lat"] is not None and row["lon"] is not None:
                distance = _haversine_miles(coords[0], coords[1], float(row["lat"]), float(row["lon"]))
            if coords and distance is not None and distance > 120:
                continue
            if destination.lower() not in (row["location_text"] or "").lower() and distance is None:
                # keep high-risk items even without location match
                if float(row["ors_score"] or 0.0) < 70.0 and float(row["tas_score"] or 0.0) < 50.0:
                    continue
            internal.append(
                {
                    "id": row["id"],
                    "title": row["title"],
                    "source": row["source_name"],
                    "ors": float(row["ors_score"] or 0.0),
                    "tas": float(row["tas_score"] or 0.0),
                    "location": row["location_text"],
                    "distance_miles": round(distance, 2) if distance is not None else None,
                }
            )

        internal.sort(key=lambda x: (x["ors"], x["tas"]), reverse=True)

        travel_feed_rows = conn.execute(
            f"""SELECT a.title, COALESCE(a.published_at, a.created_at) AS ts, s.name AS source_name
            FROM alerts a
            JOIN sources s ON s.id = a.source_id
            WHERE s.name IN (
                'State Dept Travel Alerts/Warnings',
                'CDC Travel Health Notices',
                'WHO Disease Outbreak News'
            )
              AND (LOWER(a.title) LIKE ? OR LOWER(COALESCE(a.content, '')) LIKE ?)
              {demo_filter}
            ORDER BY COALESCE(a.published_at, a.created_at) DESC
            LIMIT 20""",
            (f"%{destination.lower()}%", f"%{destination.lower()}%"),
        ).fetchall()

        gdelt_rows = conn.execute(
            f"""SELECT a.title, COALESCE(a.published_at, a.created_at) AS ts
            FROM alerts a
            JOIN sources s ON s.id = a.source_id
            WHERE s.name LIKE 'GDELT%'
              AND (LOWER(a.title) LIKE ? OR LOWER(COALESCE(a.content, '')) LIKE ?)
              {demo_filter}
            ORDER BY COALESCE(a.published_at, a.created_at) DESC
            LIMIT 20""",
            (f"%{destination.lower()}%", f"%{destination.lower()}%"),
        ).fetchall()

        lines = []
        lines.append(f"# Travel Brief: {destination}")
        lines.append("")
        lines.append(f"- Window: {start_dt} to {end_dt}")
        lines.append(f"- POI ID: {poi_id if poi_id else 'N/A'}")
        lines.append(f"- Protected Location ID: {protected_location_id if protected_location_id else 'N/A'}")
        lines.append("")

        lines.append("## Internal Alerts Near Destination")
        if internal:
            for item in internal[:20]:
                distance_text = (
                    f" | distance={item['distance_miles']}mi"
                    if item["distance_miles"] is not None
                    else ""
                )
                lines.append(
                    f"- [#{item['id']}] ORS={item['ors']:.1f} TAS={item['tas']:.1f} | "
                    f"{item['source']} | {item['title']}{distance_text}"
                )
        else:
            lines.append("- No high-confidence internal alerts for this destination/time window.")

        lines.append("")
        lines.append("## State Dept / CDC / WHO Mentions")
        if travel_feed_rows:
            for row in travel_feed_rows[:15]:
                lines.append(f"- {row['source_name']}: {row['title']}")
        else:
            lines.append("- No direct destination mentions found in these feeds.")

        lines.append("")
        lines.append("## GDELT Unrest / Protest / Violence Mentions")
        if gdelt_rows:
            for row in gdelt_rows[:15]:
                lines.append(f"- {row['title']}")
        else:
            lines.append("- No destination-tagged GDELT items found.")

        content_md = redact_text(conn, "\n".join(lines))

        brief_id = None
        if persist:
            conn.execute(
                """INSERT INTO travel_briefs
                (destination, start_dt, end_dt, content_md, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (destination, start_dt, end_dt, content_md),
            )
            brief_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()

        return {
            "id": brief_id,
            "destination": destination,
            "start_dt": start_dt,
            "end_dt": end_dt,
            "content_md": content_md,
            "internal_alerts": internal[:20],
        }
    finally:
        conn.close()
