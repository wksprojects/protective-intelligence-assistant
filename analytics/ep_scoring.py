"""Operational risk scoring for Protective Intelligence workflows."""

import re
from math import asin, cos, radians, sin, sqrt

from analytics.risk_scoring import score_to_severity
from analytics.utils import utcnow

EP_CATEGORY_BOOST = {
    "protective_intel": 10.0,
    "insider_workplace": 8.0,
    "protest_disruption": 7.0,
    "travel_risk": 6.0,
    "poi": 9.0,
    "ioc": 1.5,
    "cti_optional": 2.0,
    "threat_actor": 2.5,
    "malware": 2.5,
    "vulnerability": 2.5,
}

STATE_DEPT_SOURCE_NAME = "State Dept Travel Alerts/Warnings"
STATE_DEPT_LEVEL_CAP = {
    1: 35.0,  # Exercise normal precautions -> low
    2: 60.0,  # Exercise increased caution -> medium
    3: 80.0,  # Reconsider travel -> high
}


def _haversine_miles(lat1, lon1, lat2, lon2):
    radius_miles = 3958.756
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    return radius_miles * c


def _compute_proximity_factor(conn, alert_id):
    rows = conn.execute(
        """SELECT distance_miles, within_radius
        FROM alert_proximity
        WHERE alert_id = ?""",
        (alert_id,),
    ).fetchall()
    if not rows:
        return 0.0
    if any(int(row["within_radius"] or 0) == 1 for row in rows):
        return 15.0
    min_distance = min(float(row["distance_miles"] or 9999) for row in rows)
    if min_distance <= 5:
        return 10.0
    if min_distance <= 15:
        return 6.0
    if min_distance <= 30:
        return 3.0
    return 0.0


def _compute_event_factor(conn, alert_id):
    alert_locations = conn.execute(
        """SELECT lat, lon
        FROM alert_locations
        WHERE alert_id = ? AND lat IS NOT NULL AND lon IS NOT NULL""",
        (alert_id,),
    ).fetchall()
    if not alert_locations:
        return 0.0

    events = conn.execute(
        """SELECT lat, lon
        FROM events
        WHERE lat IS NOT NULL AND lon IS NOT NULL
          AND datetime(start_dt) >= datetime('now')
          AND datetime(start_dt) <= datetime('now', '+7 days')"""
    ).fetchall()
    if not events:
        return 0.0

    min_distance = None
    for loc in alert_locations:
        lat1 = float(loc["lat"])
        lon1 = float(loc["lon"])
        for event in events:
            distance = _haversine_miles(lat1, lon1, float(event["lat"]), float(event["lon"]))
            if min_distance is None or distance < min_distance:
                min_distance = distance
    if min_distance is None:
        return 0.0
    if min_distance <= 10:
        return 8.0
    if min_distance <= 25:
        return 4.0
    return 0.0


def _compute_poi_factor(conn, alert_id):
    count = conn.execute(
        "SELECT COUNT(*) AS c FROM poi_hits WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()["c"]
    if count <= 0:
        return 0.0
    return min(12.0, 6.0 + (count * 2.0))


def _extract_travel_advisory_level(title):
    if not title:
        return None
    match = re.search(r"\blevel\s*([1-4])\b", str(title), flags=re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except (TypeError, ValueError):
        return None


def _apply_state_dept_level_cap(source_name, title, score):
    if source_name != STATE_DEPT_SOURCE_NAME:
        return score, None
    level = _extract_travel_advisory_level(title)
    if level is None:
        return score, None
    cap = STATE_DEPT_LEVEL_CAP.get(level)
    if cap is None:
        return score, level
    return min(score, cap), level


def compute_operational_score(conn, alert_id):
    """Compute ORS for an alert and persist factor breakdown to alert_scores."""
    row = conn.execute(
        """SELECT a.id, a.keyword_id, a.title,
                  src.name AS source_name,
                  k.category,
                  s.keyword_weight, s.source_credibility,
                  s.frequency_factor, s.recency_factor
        FROM alerts a
        LEFT JOIN sources src ON src.id = a.source_id
        JOIN alert_scores s ON s.alert_id = a.id
        JOIN keywords k ON k.id = a.keyword_id
        WHERE a.id = ?
        ORDER BY s.computed_at DESC
        LIMIT 1""",
        (alert_id,),
    ).fetchone()
    if not row:
        return None

    category = (row["category"] or "").strip().lower()
    category_factor = EP_CATEGORY_BOOST.get(category, 0.0)
    proximity_factor = _compute_proximity_factor(conn, alert_id)
    event_factor = _compute_event_factor(conn, alert_id)
    poi_factor = _compute_poi_factor(conn, alert_id)

    base_score = (
        float(row["keyword_weight"] or 1.0)
        * float(row["frequency_factor"] or 1.0)
        * float(row["source_credibility"] or 0.5)
        * 20.0
    ) + (float(row["recency_factor"] or 0.1) * 10.0)

    ors_score = max(0.0, min(100.0, base_score + category_factor + proximity_factor + event_factor + poi_factor))
    ors_score, advisory_level = _apply_state_dept_level_cap(
        row["source_name"], row["title"], ors_score
    )
    ors_score = round(ors_score, 3)

    conn.execute(
        """UPDATE alert_scores
        SET category_factor = ?,
            proximity_factor = ?,
            event_factor = ?,
            poi_factor = ?,
            final_score = ?
        WHERE id = (
            SELECT id FROM alert_scores
            WHERE alert_id = ?
            ORDER BY computed_at DESC
            LIMIT 1
        )""",
        (category_factor, proximity_factor, event_factor, poi_factor, ors_score, alert_id),
    )
    conn.execute(
        "UPDATE alerts SET risk_score = ?, ors_score = ?, severity = ? WHERE id = ?",
        (ors_score, ors_score, score_to_severity(ors_score), alert_id),
    )
    return {
        "alert_id": alert_id,
        "ors_score": ors_score,
        "base_score": round(base_score, 3),
        "category_factor": category_factor,
        "proximity_factor": proximity_factor,
        "event_factor": event_factor,
        "poi_factor": poi_factor,
        "advisory_level": advisory_level,
    }


def compute_event_risk_snapshots(conn):
    upcoming = conn.execute(
        """SELECT id, lat, lon FROM events
        WHERE datetime(start_dt) >= datetime('now')
          AND datetime(start_dt) <= datetime('now', '+7 days')"""
    ).fetchall()

    alert_locations = conn.execute(
        """SELECT a.id AS alert_id, a.ors_score, al.lat, al.lon
        FROM alerts a
        JOIN alert_locations al ON al.alert_id = a.id
        WHERE a.duplicate_of IS NULL
          AND a.ors_score IS NOT NULL
          AND al.lat IS NOT NULL AND al.lon IS NOT NULL
          AND datetime(COALESCE(a.published_at, a.created_at)) >= datetime('now', '-7 days')"""
    ).fetchall()

    for event in upcoming:
        if event["lat"] is None or event["lon"] is None:
            continue
        event_lat = float(event["lat"])
        event_lon = float(event["lon"])
        nearby_scores = {}
        for row in alert_locations:
            distance = _haversine_miles(event_lat, event_lon, float(row["lat"]), float(row["lon"]))
            if distance <= 25.0:
                alert_id = int(row["alert_id"])
                score = float(row["ors_score"] or 0.0)
                previous = nearby_scores.get(alert_id)
                if previous is None or score > previous:
                    nearby_scores[alert_id] = score
        scores = list(nearby_scores.values())
        if not scores:
            continue
        scores.sort()
        ors_mean = sum(scores) / len(scores)
        p95_idx = int(max(0, min(len(scores) - 1, round((len(scores) - 1) * 0.95))))
        ors_p95 = scores[p95_idx]
        conn.execute(
            """INSERT INTO event_risk_snapshots
            (event_id, computed_at, ors_mean, ors_p95, top_drivers_json)
            VALUES (?, ?, ?, ?, ?)""",
            (
                event["id"],
                utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                round(ors_mean, 3),
                round(ors_p95, 3),
                "[]",
            ),
        )
