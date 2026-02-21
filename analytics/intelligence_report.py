"""EP-native daily intelligence reporting."""

import json
from datetime import datetime, timedelta
from math import asin, cos, radians, sin, sqrt

from analytics.governance import get_redaction_terms, redact_text
from analytics.spike_detection import detect_spikes
from analytics.utils import utcnow
from database.init_db import get_connection


def _haversine_miles(lat1, lon1, lat2, lon2):
    radius_miles = 3958.756
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    return radius_miles * c


def _severity_counts(conn, start_date, end_date, include_demo=False):
    query = """SELECT a.severity, COUNT(*) as count
        FROM alerts a
        LEFT JOIN sources s ON s.id = a.source_id
        WHERE a.created_at >= ? AND a.created_at < ?
          AND a.duplicate_of IS NULL"""
    if not include_demo:
        query += " AND COALESCE(s.source_type, '') != 'demo'"
    query += " GROUP BY a.severity"
    rows = conn.execute(query, (start_date, end_date)).fetchall()
    return {row["severity"]: row["count"] for row in rows}


def _top_operational_alerts(conn, start_date, end_date, limit=10, include_demo=False):
    query = """SELECT a.id, a.title, a.ors_score, a.tas_score, a.risk_score, a.severity,
                  a.matched_term, s.name AS source_name, k.term AS keyword, k.category
        FROM alerts a
        LEFT JOIN sources s ON s.id = a.source_id
        LEFT JOIN keywords k ON k.id = a.keyword_id
        WHERE a.created_at >= ? AND a.created_at < ?
          AND a.duplicate_of IS NULL"""
    if not include_demo:
        query += " AND COALESCE(s.source_type, '') != 'demo'"
    query += " ORDER BY COALESCE(a.ors_score, a.risk_score) DESC LIMIT ?"
    rows = conn.execute(query, (start_date, end_date, limit)).fetchall()
    return [dict(row) for row in rows]


def _top_entities_and_cves(conn, start_date, end_date, include_demo=False):
    demo_filter = ""
    if not include_demo:
        demo_filter = " AND COALESCE(s.source_type, '') != 'demo'"
    top_entities = conn.execute(
        f"""SELECT ae.entity_type AS type, ae.entity_value AS value, COUNT(*) AS mention_count
        FROM alert_entities ae
        JOIN alerts a ON a.id = ae.alert_id
        LEFT JOIN sources s ON s.id = a.source_id
        WHERE COALESCE(a.published_at, a.created_at) >= ?
          AND COALESCE(a.published_at, a.created_at) < ?
          AND a.duplicate_of IS NULL
          {demo_filter}
        GROUP BY ae.entity_type, ae.entity_value
        ORDER BY mention_count DESC
        LIMIT 20""",
        (start_date, end_date),
    ).fetchall()

    new_cves = conn.execute(
        f"""SELECT DISTINCT ae.entity_value AS value
        FROM alert_entities ae
        JOIN alerts a ON a.id = ae.alert_id
        LEFT JOIN sources s ON s.id = a.source_id
        WHERE ae.entity_type = 'cve'
          AND COALESCE(a.published_at, a.created_at) >= ?
          AND COALESCE(a.published_at, a.created_at) < ?
          AND a.duplicate_of IS NULL
          {demo_filter}
        ORDER BY ae.entity_value DESC
        LIMIT 20""",
        (start_date, end_date),
    ).fetchall()
    return [dict(row) for row in top_entities], [row["value"] for row in new_cves]


def _top_poi_status(conn, limit=10):
    rows = conn.execute(
        """SELECT pa.poi_id, p.name, p.org, p.role, pa.tas_score, pa.fixation,
                  pa.energy_burst, pa.leakage, pa.pathway, pa.targeting_specificity,
                  pa.evidence_json, pa.window_start, pa.window_end
        FROM poi_assessments pa
        JOIN pois p ON p.id = pa.poi_id
        WHERE p.active = 1
        ORDER BY pa.created_at DESC"""
    ).fetchall()

    latest = {}
    for row in rows:
        if row["poi_id"] in latest:
            continue
        payload = dict(row)
        payload["evidence"] = json.loads(payload["evidence_json"] or "{}")
        latest[row["poi_id"]] = payload
        if len(latest) >= limit:
            break
    return sorted(latest.values(), key=lambda x: x["tas_score"], reverse=True)


def _facility_watch(conn, start_date, end_date, include_demo=False):
    query = """SELECT pl.name AS protected_location,
                  COUNT(*) AS alert_count,
                  MAX(COALESCE(a.ors_score, a.risk_score)) AS max_ors,
                  SUM(CASE WHEN ap.within_radius = 1 THEN 1 ELSE 0 END) AS within_radius_count
        FROM alert_proximity ap
        JOIN protected_locations pl ON pl.id = ap.protected_location_id
        JOIN alerts a ON a.id = ap.alert_id
        LEFT JOIN sources s ON s.id = a.source_id
        WHERE datetime(COALESCE(a.published_at, a.created_at)) >= datetime(?)
          AND datetime(COALESCE(a.published_at, a.created_at)) < datetime(?)
          AND a.duplicate_of IS NULL"""
    if not include_demo:
        query += " AND COALESCE(s.source_type, '') != 'demo'"
    query += " GROUP BY pl.id ORDER BY max_ors DESC, within_radius_count DESC"
    rows = conn.execute(query, (start_date, end_date)).fetchall()
    return [dict(row) for row in rows]


def _upcoming_event_watch(conn, include_demo=False):
    events = conn.execute(
        """SELECT e.id, e.name, e.type, e.start_dt, e.end_dt, e.city, e.venue, e.lat, e.lon,
                  p.name AS poi_name
        FROM events e
        LEFT JOIN pois p ON p.id = e.poi_id
        WHERE datetime(e.start_dt) >= datetime('now')
          AND datetime(e.start_dt) <= datetime('now', '+7 days')
        ORDER BY datetime(e.start_dt) ASC"""
    ).fetchall()
    if not events:
        return []

    demo_filter = ""
    if not include_demo:
        demo_filter = " AND COALESCE(s.source_type, '') != 'demo'"
    recent_alert_locations = conn.execute(
        f"""SELECT a.id AS alert_id, COALESCE(a.ors_score, a.risk_score, 0) AS ors_score,
                  al.lat, al.lon
        FROM alerts a
        JOIN alert_locations al ON al.alert_id = a.id
        LEFT JOIN sources s ON s.id = a.source_id
        WHERE a.duplicate_of IS NULL
          AND al.lat IS NOT NULL AND al.lon IS NOT NULL
          AND datetime(COALESCE(a.published_at, a.created_at)) >= datetime('now', '-7 days')
          {demo_filter}"""
    ).fetchall()

    output = []
    for event in events:
        payload = dict(event)
        nearby_scores = {}
        if event["lat"] is not None and event["lon"] is not None:
            event_lat = float(event["lat"])
            event_lon = float(event["lon"])
            for row in recent_alert_locations:
                distance = _haversine_miles(event_lat, event_lon, float(row["lat"]), float(row["lon"]))
                if distance <= 25.0:
                    alert_id = int(row["alert_id"])
                    score = float(row["ors_score"] or 0.0)
                    previous = nearby_scores.get(alert_id)
                    if previous is None or score > previous:
                        nearby_scores[alert_id] = score
        payload["max_ors"] = round(max(nearby_scores.values()), 3) if nearby_scores else 0.0
        payload["nearby_alerts"] = len(nearby_scores)
        output.append(payload)
    return output


def _build_executive_summary(report_date, total, critical, high, prev_total, top_ops, top_pois):
    delta = total - prev_total
    direction = "up" if delta > 0 else "down" if delta < 0 else "flat"

    changes = []
    changes.append(f"Alert volume is {direction} ({total} vs {prev_total} yesterday).")
    if top_ops:
        changes.append(
            f"Top operational driver: '{top_ops[0]['title'][:90]}' (ORS {float(top_ops[0].get('ors_score') or top_ops[0].get('risk_score') or 0):.1f})."
        )
    if top_pois:
        changes.append(
            f"Highest protectee escalation: {top_pois[0]['name']} (TAS {float(top_pois[0]['tas_score']):.1f})."
        )

    return (
        f"EP Summary for {report_date}: {total} unique alerts, {critical} critical, {high} high. "
        + " ".join(changes[:3])
    )


def _build_escalations(top_ops, top_pois, facility_watch):
    escalations = []
    for alert in top_ops[:5]:
        ors = float(alert.get("ors_score") or alert.get("risk_score") or 0.0)
        tas = float(alert.get("tas_score") or 0.0)
        if ors >= 85 or tas >= 70:
            escalations.append(
                {
                    "priority": "IMMEDIATE",
                    "type": "operational_or_targeting",
                    "alert_id": alert["id"],
                    "title": alert["title"],
                    "ors": round(ors, 2),
                    "tas": round(tas, 2),
                    "why": "High ORS/TAS indicates potential targeting with operational relevance.",
                }
            )
    for poi in top_pois[:5]:
        if float(poi.get("tas_score") or 0) >= 60:
            escalations.append(
                {
                    "priority": "HIGH",
                    "type": "poi_escalation",
                    "poi": poi["name"],
                    "tas": round(float(poi["tas_score"]), 2),
                    "why": "TRAP-lite flags indicate escalating attention toward protectee.",
                }
            )
    for facility in facility_watch[:5]:
        if int(facility.get("within_radius_count") or 0) > 0:
            escalations.append(
                {
                    "priority": "HIGH",
                    "type": "facility_watch",
                    "facility": facility["protected_location"],
                    "within_radius": int(facility.get("within_radius_count") or 0),
                    "why": "Threat-related alerts are occurring within protected radius.",
                }
            )

    if not escalations:
        escalations.append(
            {
                "priority": "MEDIUM",
                "type": "monitoring",
                "why": "No immediate escalation trigger; continue monitoring and validation.",
            }
        )
    priority_order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2}
    escalations.sort(key=lambda x: priority_order.get(x.get("priority", "MEDIUM"), 3))
    return escalations


def _apply_redaction(conn, report):
    redaction_terms = get_redaction_terms(conn)
    report["executive_summary"] = redact_text(
        conn, report.get("executive_summary", ""), redaction_terms=redaction_terms
    )
    for item in report.get("top_risks", []):
        item["title"] = redact_text(conn, item.get("title", ""), redaction_terms=redaction_terms)
    for item in report.get("protectee_status", []):
        item["name"] = redact_text(conn, item.get("name", ""), redaction_terms=redaction_terms)
        for excerpt_idx, excerpt in enumerate(item.get("evidence", {}).get("excerpts", [])):
            item["evidence"]["excerpts"][excerpt_idx] = redact_text(
                conn, excerpt, redaction_terms=redaction_terms
            )
    for item in report.get("escalation_recommendations", []):
        if "title" in item:
            item["title"] = redact_text(conn, item["title"], redaction_terms=redaction_terms)
        if "poi" in item:
            item["poi"] = redact_text(conn, item["poi"], redaction_terms=redaction_terms)
    return report


def generate_daily_report(report_date=None, include_demo=False):
    conn = get_connection()
    try:
        if report_date is None:
            report_date = utcnow().strftime("%Y-%m-%d")

        day_start = report_date
        day_end = (datetime.strptime(report_date, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
        prev_day = (datetime.strptime(report_date, "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d")

        top_ops = _top_operational_alerts(conn, day_start, day_end, limit=10, include_demo=include_demo)
        severity_map = _severity_counts(conn, day_start, day_end, include_demo=include_demo)
        prev_severity_map = _severity_counts(conn, prev_day, report_date, include_demo=include_demo)
        total = sum(severity_map.values())
        prev_total = sum(prev_severity_map.values())

        spikes = detect_spikes(threshold=1.5, as_of_date=report_date)
        top_entities, new_cves = _top_entities_and_cves(
            conn, day_start, day_end, include_demo=include_demo
        )
        top_pois = _top_poi_status(conn, limit=10)
        facility_watch = _facility_watch(conn, day_start, day_end, include_demo=include_demo)
        upcoming_events = _upcoming_event_watch(conn, include_demo=include_demo)
        escalations = _build_escalations(top_ops, top_pois, facility_watch)

        executive_summary = _build_executive_summary(
            report_date,
            total,
            severity_map.get("critical", 0),
            severity_map.get("high", 0),
            prev_total,
            top_ops,
            top_pois,
        )

        report = {
            "report_date": report_date,
            "executive_summary": executive_summary,
            "top_risks": top_ops,
            "protectee_status": top_pois,
            "facility_watch": facility_watch,
            "upcoming_events": upcoming_events,
            "emerging_themes": spikes,
            "active_threat_actors": [],
            "escalation_recommendations": escalations,
            "top_entities": top_entities,
            "new_cves": new_cves,
            "stats": {
                "total_alerts": total,
                "critical_count": severity_map.get("critical", 0),
                "high_count": severity_map.get("high", 0),
                "medium_count": severity_map.get("medium", 0),
                "low_count": severity_map.get("low", 0),
            },
        }
        report = _apply_redaction(conn, report)

        conn.execute(
            """INSERT INTO intelligence_reports
            (report_date, executive_summary, top_risks, emerging_themes,
             active_threat_actors, escalation_recommendations, top_entities,
             new_cves, total_alerts, critical_count, high_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(report_date) DO UPDATE SET
                executive_summary = excluded.executive_summary,
                top_risks = excluded.top_risks,
                emerging_themes = excluded.emerging_themes,
                active_threat_actors = excluded.active_threat_actors,
                escalation_recommendations = excluded.escalation_recommendations,
                top_entities = excluded.top_entities,
                new_cves = excluded.new_cves,
                total_alerts = excluded.total_alerts,
                critical_count = excluded.critical_count,
                high_count = excluded.high_count,
                generated_at = CURRENT_TIMESTAMP""",
            (
                report_date,
                report["executive_summary"],
                json.dumps(report["top_risks"]),
                json.dumps(report["emerging_themes"]),
                json.dumps(report["active_threat_actors"]),
                json.dumps(report["escalation_recommendations"]),
                json.dumps(report["top_entities"]),
                json.dumps(report["new_cves"]),
                report["stats"]["total_alerts"],
                report["stats"]["critical_count"],
                report["stats"]["high_count"],
            ),
        )
        conn.commit()
        return report
    finally:
        conn.close()
