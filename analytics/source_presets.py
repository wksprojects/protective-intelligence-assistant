"""Targeted source preset expansion for event/location monitoring."""

import re
import string

from analytics.utils import parse_timestamp, utcnow
from database.init_db import build_gdelt_rss_url, get_connection, load_watchlist_yaml


def _slugify(value):
    cleaned = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower())
    return cleaned.strip("-")


def _safe_format(template, context):
    if not template:
        return ""

    class _SafeDict(dict):
        def __missing__(self, key):
            return ""

    return string.Formatter().vformat(template, (), _SafeDict(context)).strip()


def _build_event_contexts(conn, horizon_days=30):
    safe_horizon = max(1, min(int(horizon_days), 120))
    rows = conn.execute(
        """SELECT e.id, e.name, e.start_dt, e.end_dt, e.city, e.country, e.venue,
                  p.name AS poi_name, p.org AS poi_org
        FROM events e
        LEFT JOIN pois p ON p.id = e.poi_id
        WHERE datetime(e.start_dt) >= datetime('now')
          AND datetime(e.start_dt) <= datetime('now', ?)
        ORDER BY datetime(e.start_dt) ASC""",
        (f"+{safe_horizon} days",),
    ).fetchall()
    contexts = []
    for row in rows:
        start_dt = parse_timestamp(row["start_dt"])
        contexts.append(
            {
                "scope_id": int(row["id"]),
                "scope_label": row["name"],
                "scope_type": "event",
                "event_name": row["name"] or "",
                "event_slug": _slugify(row["name"]),
                "start_dt": row["start_dt"] or "",
                "start_date": start_dt.strftime("%Y-%m-%d") if start_dt else "",
                "city": row["city"] or "",
                "city_slug": _slugify(row["city"]),
                "country": row["country"] or "",
                "country_slug": _slugify(row["country"]),
                "venue": row["venue"] or "",
                "venue_slug": _slugify(row["venue"]),
                "poi_name": row["poi_name"] or "",
                "poi_slug": _slugify(row["poi_name"]),
                "poi_org": row["poi_org"] or "",
                "poi_org_slug": _slugify(row["poi_org"]),
            }
        )
    return contexts


def _build_location_contexts(conn):
    rows = conn.execute(
        """SELECT id, name, type, notes
        FROM protected_locations
        WHERE active = 1
        ORDER BY name""",
    ).fetchall()
    contexts = []
    for row in rows:
        contexts.append(
            {
                "scope_id": int(row["id"]),
                "scope_label": row["name"],
                "scope_type": "location",
                "location_name": row["name"] or "",
                "location_slug": _slugify(row["name"]),
                "location_type": row["type"] or "",
                "location_type_slug": _slugify(row["type"]),
                "location_notes": row["notes"] or "",
            }
        )
    return contexts


def preview_targeted_source_presets(
    horizon_days=30,
    max_contexts_per_preset=5,
):
    watchlist = load_watchlist_yaml()
    presets = (watchlist or {}).get("targeted_source_presets", [])
    if not presets:
        return {"as_of": utcnow().strftime("%Y-%m-%d %H:%M:%S"), "presets": []}

    conn = get_connection()
    try:
        contexts = {
            "event": _build_event_contexts(conn, horizon_days=horizon_days),
            "location": _build_location_contexts(conn),
        }
    finally:
        conn.close()

    safe_max_contexts = max(1, min(int(max_contexts_per_preset), 20))
    expanded = []
    for preset in presets:
        scope = preset.get("scope")
        context_rows = contexts.get(scope, [])
        preview_rows = []
        for context in context_rows[:safe_max_contexts]:
            name_template = preset.get("name_template") or preset.get("name") or ""
            suggested_name = _safe_format(name_template, context) or preset.get("name")

            raw_url_template = preset.get("url_template")
            raw_gdelt_template = preset.get("gdelt_query_template")
            gdelt_query = _safe_format(raw_gdelt_template, context) if raw_gdelt_template else None
            suggested_url = _safe_format(raw_url_template, context) if raw_url_template else None
            if not suggested_url and gdelt_query:
                try:
                    suggested_url = build_gdelt_rss_url(gdelt_query)
                except (TypeError, ValueError):
                    suggested_url = None

            preview_rows.append(
                {
                    "scope_type": context["scope_type"],
                    "scope_id": context["scope_id"],
                    "scope_label": context["scope_label"],
                    "suggested_name": suggested_name,
                    "suggested_url": suggested_url,
                    "gdelt_query": gdelt_query,
                    "source_type": preset.get("source_type"),
                    "credibility_score": preset.get("credibility_score"),
                }
            )

        expanded.append(
            {
                "name": preset.get("name"),
                "scope": scope,
                "source_type": preset.get("source_type"),
                "enabled": bool(preset.get("enabled")),
                "notes": preset.get("notes"),
                "preview": preview_rows,
            }
        )

    return {
        "as_of": utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "horizon_days": max(1, min(int(horizon_days), 120)),
        "presets": expanded,
    }
