import json
import os
import secrets
import sys
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database.init_db import (
    get_connection,
    init_db,
    migrate_schema,
    seed_default_events,
    seed_default_keywords,
    seed_default_pois,
    seed_default_protected_locations,
    seed_default_sources,
    seed_threat_actors,
)

# --- API Key Authentication ---
# Set PI_API_KEY (preferred) or OSINT_API_KEY (legacy) to enable auth.
# When neither is set, auth is disabled (local-only development mode).
def _resolve_api_key():
    return os.getenv("PI_API_KEY") or os.getenv("OSINT_API_KEY", "")


_API_KEY = _resolve_api_key()
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: Optional[str] = Security(_api_key_header)):
    """Verify the API key for mutation endpoints.

    Reads PI_API_KEY first, then OSINT_API_KEY for backward compatibility.
    When neither is set, auth is bypassed (development mode).
    When set, all mutation endpoints require a matching X-API-Key header.
    """
    if not _API_KEY:
        return  # Auth disabled — development mode
    if not api_key or not secrets.compare_digest(api_key, _API_KEY):
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing API key. Set X-API-Key header.",
        )


app = FastAPI(
    title="Protective Intelligence Assistant API",
    description="EP-focused REST API: protectee/facility/travel triage, ORS/TAS scoring, behavioral threat assessment, SITREPs, and explainable uncertainty.",
    version="5.0.0",
)


# --- Models ---


class KeywordCreate(BaseModel):
    term: str
    category: str = "general"
    weight: float = 1.0


class ClassifyRequest(BaseModel):
    classification: str  # "true_positive" or "false_positive"


class POICreate(BaseModel):
    name: str
    org: Optional[str] = None
    role: Optional[str] = None
    sensitivity: int = 3
    aliases: list[str] = []


class ProtectedLocationCreate(BaseModel):
    name: str
    type: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius_miles: float = 5.0
    notes: Optional[str] = None


class TravelBriefRequest(BaseModel):
    destination: str
    start_dt: str
    end_dt: str
    poi_id: Optional[int] = None
    protected_location_id: Optional[int] = None


class DispositionRequest(BaseModel):
    status: str
    rationale: Optional[str] = None
    user: Optional[str] = "analyst"


class AlertResponse(BaseModel):
    id: int
    title: str
    content: Optional[str]
    url: Optional[str]
    risk_score: Optional[float] = None
    severity: str
    reviewed: int
    published_at: Optional[str] = None
    created_at: str
    source_name: Optional[str] = None
    matched_term: Optional[str] = None


# --- Startup ---


@app.on_event("startup")
def startup():
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

    # Seed only on first-run empty tables; do not overwrite analyst-tuned values.
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


@app.get("/")
def root():
    return {"status": "online", "service": "Protective Intelligence Assistant", "version": "5.0.0"}


# --- ALERTS ---


@app.get("/alerts", dependencies=[Depends(verify_api_key)])
def get_alerts(
    severity: Optional[str] = None,
    reviewed: Optional[int] = None,
    min_score: Optional[float] = None,
    sort_by: str = Query(default="risk_score", pattern="^(risk_score|created_at|published_at)$"),
    limit: int = Query(default=50, le=500),
    offset: int = 0,
):
    conn = get_connection()
    query = """
        SELECT a.id, a.title, a.content, a.url, a.risk_score, a.ors_score, a.tas_score, a.severity,
               a.reviewed, a.published_at, a.created_at, a.content_hash, a.duplicate_of,
               s.name as source_name, k.term as matched_term
        FROM alerts a
        LEFT JOIN sources s ON a.source_id = s.id
        LEFT JOIN keywords k ON a.keyword_id = k.id
        WHERE 1=1
    """
    params = []

    if severity:
        query += " AND a.severity = ?"
        params.append(severity)
    if reviewed is not None:
        query += " AND a.reviewed = ?"
        params.append(reviewed)
    if min_score is not None:
        query += " AND a.risk_score >= ?"
        params.append(min_score)

    query += f" ORDER BY a.{sort_by} DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    alerts = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(a) for a in alerts]


@app.get("/alerts/summary", dependencies=[Depends(verify_api_key)])
def get_alerts_summary():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as count FROM alerts").fetchone()["count"]
    unique = conn.execute(
        "SELECT COUNT(*) as count FROM alerts WHERE duplicate_of IS NULL"
    ).fetchone()["count"]
    by_severity = conn.execute(
        "SELECT severity, COUNT(*) as count FROM alerts WHERE duplicate_of IS NULL GROUP BY severity"
    ).fetchall()
    by_source = conn.execute(
        """SELECT s.name, COUNT(*) as count FROM alerts a
        JOIN sources s ON a.source_id = s.id
        WHERE a.duplicate_of IS NULL
        GROUP BY s.name ORDER BY count DESC"""
    ).fetchall()
    top_keywords = conn.execute(
        """SELECT k.term, COUNT(*) as count FROM alerts a
        JOIN keywords k ON a.keyword_id = k.id
        WHERE a.duplicate_of IS NULL
        GROUP BY k.term ORDER BY count DESC LIMIT 10"""
    ).fetchall()
    unreviewed = conn.execute(
        "SELECT COUNT(*) as count FROM alerts WHERE reviewed = 0 AND duplicate_of IS NULL"
    ).fetchone()["count"]
    avg_score_row = conn.execute(
        "SELECT AVG(COALESCE(ors_score, risk_score)) as avg FROM alerts WHERE reviewed = 0 AND duplicate_of IS NULL"
    ).fetchone()
    avg_risk_score = round(avg_score_row["avg"], 1) if avg_score_row["avg"] else 0.0
    avg_tas_row = conn.execute(
        "SELECT AVG(tas_score) as avg FROM alerts WHERE reviewed = 0 AND duplicate_of IS NULL"
    ).fetchone()
    avg_tas_score = round(avg_tas_row["avg"], 1) if avg_tas_row["avg"] else 0.0

    # Count active spikes
    from analytics.spike_detection import detect_spikes

    active_spikes = len(detect_spikes(threshold=2.0))

    # Duplicate stats
    duplicates = total - unique

    conn.close()
    return {
        "total_alerts": total,
        "unique_alerts": unique,
        "duplicates": duplicates,
        "unreviewed": unreviewed,
        "avg_risk_score": avg_risk_score,
        "avg_tas_score": avg_tas_score,
        "active_spikes": active_spikes,
        "by_severity": {row["severity"]: row["count"] for row in by_severity},
        "by_source": {row["name"]: row["count"] for row in by_source},
        "top_keywords": {row["term"]: row["count"] for row in top_keywords},
    }


@app.patch("/alerts/{alert_id}/review", dependencies=[Depends(verify_api_key)])
def mark_reviewed(alert_id: int):
    conn = get_connection()
    result = conn.execute("UPDATE alerts SET reviewed = 1 WHERE id = ?", (alert_id,))
    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")
    conn.commit()
    conn.close()
    return {"status": "reviewed", "alert_id": alert_id}


@app.patch("/alerts/{alert_id}/classify", dependencies=[Depends(verify_api_key)])
def classify_alert(alert_id: int, body: ClassifyRequest):
    """
    Classify an alert as true_positive or false_positive.
    Updates the source's Bayesian credibility (alpha/beta).
    """
    from analytics.risk_scoring import update_source_credibility_bayesian

    if body.classification not in ("true_positive", "false_positive"):
        raise HTTPException(
            status_code=400,
            detail="classification must be 'true_positive' or 'false_positive'",
        )

    conn = get_connection()
    alert = conn.execute("SELECT source_id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    # Mark as reviewed
    conn.execute("UPDATE alerts SET reviewed = 1 WHERE id = ?", (alert_id,))

    # Update Bayesian credibility
    is_tp = body.classification == "true_positive"
    update_source_credibility_bayesian(conn, alert["source_id"], is_tp)

    conn.commit()

    # Return updated source credibility
    source = conn.execute(
        "SELECT name, credibility_score, bayesian_alpha, bayesian_beta, true_positives, false_positives FROM sources WHERE id = ?",
        (alert["source_id"],),
    ).fetchone()
    conn.close()

    return {
        "status": "classified",
        "alert_id": alert_id,
        "classification": body.classification,
        "source_name": source["name"],
        "updated_credibility": source["credibility_score"],
        "bayesian_alpha": source["bayesian_alpha"],
        "bayesian_beta": source["bayesian_beta"],
        "true_positives": source["true_positives"],
        "false_positives": source["false_positives"],
    }


@app.get("/alerts/{alert_id}/score", dependencies=[Depends(verify_api_key)])
def get_alert_score(
    alert_id: int,
    uncertainty: int = Query(default=0, ge=0, le=1),
    n: int = Query(default=500, ge=100, le=5000),
    force: int = Query(default=0, ge=0, le=1),
):
    """Get the score breakdown for a specific alert, including Monte Carlo interval stats.

    When uncertainty is enabled, severity_adjusted is derived from the
    interval mean rather than the point estimate to reduce oscillation
    near severity boundaries.
    """
    from analytics.risk_scoring import score_to_severity_with_uncertainty
    from analytics.uncertainty import compute_uncertainty_for_alert

    conn = get_connection()
    score = conn.execute(
        """SELECT * FROM alert_scores WHERE alert_id = ?
        ORDER BY computed_at DESC LIMIT 1""",
        (alert_id,),
    ).fetchone()
    alert_row = conn.execute(
        "SELECT id, risk_score, ors_score, tas_score, severity FROM alerts WHERE id = ?",
        (alert_id,),
    ).fetchone()
    if not score:
        conn.close()
        raise HTTPException(status_code=404, detail="Score not found for alert")
    if not alert_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")
    conn.close()

    payload = dict(score)
    payload["ors_score"] = alert_row["ors_score"]
    payload["tas_score"] = alert_row["tas_score"]
    payload["severity"] = alert_row["severity"]
    if uncertainty == 1:
        try:
            interval = compute_uncertainty_for_alert(
                alert_id=alert_id,
                n=n,
                force=bool(force),
            )
            payload["uncertainty"] = interval
            # Derive severity from interval mean to avoid boundary oscillation
            severity_adj, used_score = score_to_severity_with_uncertainty(
                payload.get("final_score", 0), interval.get("mean")
            )
            payload["severity_adjusted"] = severity_adj
            payload["severity_score_basis"] = round(used_score, 3)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
    return payload


@app.get("/alerts/{alert_id}/entities", dependencies=[Depends(verify_api_key)])
def get_alert_entities(alert_id: int):
    conn = get_connection()
    alert = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    entities = conn.execute(
        """SELECT id, entity_type, entity_value, created_at
        FROM alert_entities
        WHERE alert_id = ?
        ORDER BY entity_type, entity_value""",
        (alert_id,),
    ).fetchall()
    conn.close()
    return [dict(entity) for entity in entities]


@app.get("/alerts/{alert_id}/iocs", dependencies=[Depends(verify_api_key)])
def get_alert_iocs(alert_id: int):
    conn = get_connection()
    alert = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    iocs = conn.execute(
        """SELECT id, entity_type AS type, entity_value AS value
        FROM alert_entities
        WHERE alert_id = ?
          AND entity_type IN ('ipv4', 'domain', 'url', 'cve', 'md5', 'sha1', 'sha256')
        ORDER BY entity_type, entity_value""",
        (alert_id,),
    ).fetchall()
    conn.close()
    return [dict(ioc) for ioc in iocs]


@app.post("/alerts/rescore", dependencies=[Depends(verify_api_key)])
def trigger_rescore():
    """Re-score all unreviewed alerts with current weights and frequencies."""
    from analytics.risk_scoring import rescore_all_alerts

    conn = get_connection()
    count = rescore_all_alerts(conn)
    conn.close()
    return {"status": "complete", "alerts_rescored": count}


# --- INTELLIGENCE REPORTS ---


@app.get("/intelligence/daily", dependencies=[Depends(verify_api_key)])
def get_daily_report(date: Optional[str] = None):
    """Generate or retrieve the intelligence report for a given date."""
    from analytics.intelligence_report import generate_daily_report

    if date is not None:
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail="Invalid date format. Use YYYY-MM-DD.",
            ) from e
    report = generate_daily_report(report_date=date)
    return report


@app.get("/intelligence/reports", dependencies=[Depends(verify_api_key)])
def list_reports(limit: int = Query(default=7, le=30)):
    """List recent intelligence reports."""
    conn = get_connection()
    reports = conn.execute(
        """SELECT id, report_date, total_alerts, critical_count, high_count, generated_at
        FROM intelligence_reports
        ORDER BY report_date DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in reports]


@app.get("/intelligence/reports/{report_date}", dependencies=[Depends(verify_api_key)])
def get_report(report_date: str):
    """Retrieve a specific day's intelligence report."""
    conn = get_connection()
    report = conn.execute(
        "SELECT * FROM intelligence_reports WHERE report_date = ?",
        (report_date,),
    ).fetchone()
    conn.close()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    result = dict(report)
    for field in (
        "top_risks",
        "emerging_themes",
        "active_threat_actors",
        "escalation_recommendations",
        "top_entities",
        "new_cves",
    ):
        if result.get(field):
            result[field] = json.loads(result[field])
    return result


# --- ANALYTICS ---


@app.get("/analytics/spikes", dependencies=[Depends(verify_api_key)])
def get_spikes(
    threshold: float = Query(default=2.0, ge=1.0),
    date: Optional[str] = Query(default=None),
):
    """Get keywords with unusual frequency spikes (includes Z-score)."""
    from analytics.spike_detection import detect_spikes

    if date is not None:
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail="Invalid date format. Use YYYY-MM-DD.",
            ) from e
    return detect_spikes(threshold=threshold, as_of_date=date)


@app.get("/analytics/keyword-trend/{keyword_id}", dependencies=[Depends(verify_api_key)])
def get_keyword_trend_endpoint(keyword_id: int, days: int = Query(default=14, le=60)):
    """Get daily frequency trend for a specific keyword."""
    from analytics.spike_detection import get_keyword_trend

    return get_keyword_trend(keyword_id, days=days)


@app.get("/analytics/forecast/keyword/{keyword_id}", dependencies=[Depends(verify_api_key)])
def get_keyword_forecast(keyword_id: int, horizon: int = Query(default=7, ge=1, le=30)):
    """Forecast keyword frequency for the next N days."""
    from analytics.forecasting import forecast_keyword

    return forecast_keyword(keyword_id=keyword_id, horizon=horizon)


@app.get("/analytics/evaluation", dependencies=[Depends(verify_api_key)])
def get_evaluation_metrics(source_id: Optional[int] = None):
    """
    Compute and return precision/recall/F1 per source.
    Based on TP/FP classifications from alert reviews.
    """
    from analytics.risk_scoring import compute_evaluation_metrics

    conn = get_connection()
    if source_id is not None:
        source = conn.execute(
            "SELECT id FROM sources WHERE id = ?",
            (source_id,),
        ).fetchone()
        if not source:
            conn.close()
            raise HTTPException(status_code=404, detail="Source not found")
    results = compute_evaluation_metrics(conn, source_id=source_id)
    conn.close()
    return results


@app.get("/analytics/performance", dependencies=[Depends(verify_api_key)])
def get_performance_metrics(limit: int = Query(default=20, le=100)):
    """Get recent scraping performance benchmarks."""
    conn = get_connection()
    runs = conn.execute(
        """SELECT * FROM scrape_runs
        ORDER BY started_at DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in runs]


@app.get("/analytics/backtest", dependencies=[Depends(verify_api_key)])
def run_backtest():
    """
    Run scoring model backtest against golden dataset of known incidents.
    Compares multi-factor scoring vs naive baseline.
    """
    from analytics.backtesting import run_backtest

    return run_backtest()


@app.get("/analytics/duplicates", dependencies=[Depends(verify_api_key)])
def get_duplicate_stats():
    """Get content deduplication statistics."""
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as count FROM alerts").fetchone()["count"]
    unique = conn.execute(
        "SELECT COUNT(*) as count FROM alerts WHERE duplicate_of IS NULL"
    ).fetchone()["count"]
    duplicates = total - unique

    # Top duplicate clusters (original alerts with most duplicates)
    clusters = conn.execute(
        """SELECT a.id, a.title, a.content_hash, COUNT(d.id) as dup_count
        FROM alerts a
        JOIN alerts d ON d.duplicate_of = a.id
        GROUP BY a.id
        ORDER BY dup_count DESC
        LIMIT 10"""
    ).fetchall()

    conn.close()
    return {
        "total_alerts": total,
        "unique_alerts": unique,
        "duplicates": duplicates,
        "dedup_ratio": round(duplicates / total, 4) if total > 0 else 0.0,
        "top_clusters": [dict(c) for c in clusters],
    }


@app.get("/analytics/graph", dependencies=[Depends(verify_api_key)])
def get_graph(
    days: int = Query(default=7, ge=1, le=30),
    min_score: float = Query(default=70.0, ge=0.0, le=100.0),
    limit_alerts: int = Query(default=500, ge=10, le=2000),
):
    """Build a compact link-analysis graph across sources, keywords, entities, and IOCs."""
    from analytics.graph import build_graph

    return build_graph(days=days, min_score=min_score, limit_alerts=limit_alerts)


# --- PROTECTIVE INTEL ---


@app.get("/pois", dependencies=[Depends(verify_api_key)])
def get_pois(active_only: int = Query(default=1, ge=0, le=1)):
    conn = get_connection()
    query = "SELECT * FROM pois"
    if active_only == 1:
        query += " WHERE active = 1"
    query += " ORDER BY sensitivity DESC, name"
    pois = [dict(row) for row in conn.execute(query).fetchall()]
    poi_ids = [poi["id"] for poi in pois]
    aliases_by_poi = {poi_id: [] for poi_id in poi_ids}
    if poi_ids:
        placeholders = ",".join("?" for _ in poi_ids)
        alias_rows = conn.execute(
            f"""SELECT id, poi_id, alias, alias_type, active
            FROM poi_aliases
            WHERE poi_id IN ({placeholders})
            ORDER BY alias""",
            poi_ids,
        ).fetchall()
        for alias in alias_rows:
            alias_payload = dict(alias)
            poi_id = alias_payload.pop("poi_id")
            aliases_by_poi.setdefault(poi_id, []).append(alias_payload)
    for poi in pois:
        poi["aliases"] = aliases_by_poi.get(poi["id"], [])
    conn.close()
    return pois


@app.post("/pois", dependencies=[Depends(verify_api_key)])
def create_poi(body: POICreate):
    conn = get_connection()
    conn.execute(
        "INSERT INTO pois (name, org, role, sensitivity, active) VALUES (?, ?, ?, ?, 1)",
        (body.name.strip(), body.org, body.role, max(1, min(int(body.sensitivity), 5))),
    )
    poi_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    alias_values = body.aliases or [body.name]
    for alias in alias_values:
        alias_text = alias.strip()
        if not alias_text:
            continue
        conn.execute(
            "INSERT INTO poi_aliases (poi_id, alias, alias_type, active) VALUES (?, ?, ?, 1)",
            (poi_id, alias_text, "name"),
        )
    conn.commit()
    poi = conn.execute("SELECT * FROM pois WHERE id = ?", (poi_id,)).fetchone()
    aliases = conn.execute(
        "SELECT id, alias, alias_type, active FROM poi_aliases WHERE poi_id = ? ORDER BY alias",
        (poi_id,),
    ).fetchall()
    conn.close()
    payload = dict(poi)
    payload["aliases"] = [dict(alias) for alias in aliases]
    return payload


@app.get("/pois/{poi_id}/hits", dependencies=[Depends(verify_api_key)])
def get_poi_hits(poi_id: int, days: int = Query(default=14, ge=1, le=90)):
    conn = get_connection()
    exists = conn.execute("SELECT id FROM pois WHERE id = ?", (poi_id,)).fetchone()
    if not exists:
        conn.close()
        raise HTTPException(status_code=404, detail="POI not found")
    rows = conn.execute(
        """SELECT ph.id, ph.match_type, ph.match_value, ph.match_score, ph.context, ph.created_at,
                  a.id AS alert_id, a.title, a.ors_score, a.tas_score, a.severity,
                  COALESCE(a.published_at, a.created_at) AS timestamp
        FROM poi_hits ph
        JOIN alerts a ON a.id = ph.alert_id
        WHERE ph.poi_id = ?
          AND datetime(COALESCE(a.published_at, a.created_at)) >= datetime('now', ?)
        ORDER BY COALESCE(a.published_at, a.created_at) DESC""",
        (poi_id, f"-{int(days)} days"),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/pois/{poi_id}/assessment", dependencies=[Depends(verify_api_key)])
def get_poi_assessment(
    poi_id: int,
    window_days: int = Query(default=14, ge=7, le=30),
    force: int = Query(default=0, ge=0, le=1),
):
    """Get the TAS (Threat Assessment Score) for a protectee.

    Returns TRAP-lite flags, evidence, uncertainty interval, and an
    ``escalation`` block explaining *why* to escalate, which flags fired,
    evidence strings, recommended analyst actions, and notification tier.
    """
    from analytics.tas_assessment import build_escalation_explanation, compute_poi_assessment

    conn = get_connection()
    exists = conn.execute("SELECT id FROM pois WHERE id = ?", (poi_id,)).fetchone()
    if not exists:
        conn.close()
        raise HTTPException(status_code=404, detail="POI not found")

    if force == 1:
        assessment = compute_poi_assessment(conn, poi_id, window_days=window_days)
        conn.commit()
        conn.close()
        if assessment:
            assessment["escalation"] = build_escalation_explanation(assessment)
        return assessment or {}

    row = conn.execute(
        """SELECT * FROM poi_assessments
        WHERE poi_id = ?
        ORDER BY created_at DESC
        LIMIT 1""",
        (poi_id,),
    ).fetchone()
    if row:
        payload = dict(row)
        payload["evidence"] = json.loads(payload.get("evidence_json") or "{}")
        payload["escalation"] = build_escalation_explanation(payload)
        conn.close()
        return payload

    assessment = compute_poi_assessment(conn, poi_id, window_days=window_days)
    conn.commit()
    conn.close()
    if assessment:
        assessment["escalation"] = build_escalation_explanation(assessment)
    return assessment or {}


@app.get("/locations/protected", dependencies=[Depends(verify_api_key)])
def get_protected_locations(active_only: int = Query(default=1, ge=0, le=1)):
    conn = get_connection()
    query = "SELECT * FROM protected_locations"
    if active_only == 1:
        query += " WHERE active = 1"
    query += " ORDER BY name"
    rows = conn.execute(query).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/locations/protected/{location_id}/alerts", dependencies=[Depends(verify_api_key)])
def get_protected_location_alerts(
    location_id: int,
    days: int = Query(default=7, ge=1, le=30),
    min_ors: float = Query(default=50.0, ge=0.0, le=100.0),
):
    conn = get_connection()
    exists = conn.execute(
        "SELECT id FROM protected_locations WHERE id = ?",
        (location_id,),
    ).fetchone()
    if not exists:
        conn.close()
        raise HTTPException(status_code=404, detail="Protected location not found")
    rows = conn.execute(
        """SELECT a.id, a.title, a.ors_score, a.tas_score, a.severity,
                  COALESCE(a.published_at, a.created_at) AS timestamp,
                  MIN(ap.distance_miles) AS distance_miles,
                  MAX(ap.within_radius) AS within_radius,
                  GROUP_CONCAT(DISTINCT al.location_text) AS location_text
        FROM alert_proximity ap
        JOIN alerts a ON a.id = ap.alert_id
        LEFT JOIN alert_locations al ON al.alert_id = a.id
        WHERE ap.protected_location_id = ?
          AND datetime(COALESCE(a.published_at, a.created_at)) >= datetime('now', ?)
          AND COALESCE(a.ors_score, a.risk_score) >= ?
          AND a.duplicate_of IS NULL
        GROUP BY a.id, a.title, a.ors_score, a.tas_score, a.severity, COALESCE(a.published_at, a.created_at)
        ORDER BY COALESCE(a.ors_score, a.risk_score) DESC""",
        (location_id, f"-{int(days)} days", float(min_ors)),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.post("/locations/protected", dependencies=[Depends(verify_api_key)])
def create_protected_location(body: ProtectedLocationCreate):
    conn = get_connection()
    conn.execute(
        """INSERT INTO protected_locations
        (name, type, lat, lon, radius_miles, active, notes)
        VALUES (?, ?, ?, ?, ?, 1, ?)""",
        (body.name.strip(), body.type, body.lat, body.lon, body.radius_miles, body.notes),
    )
    location_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    row = conn.execute(
        "SELECT * FROM protected_locations WHERE id = ?",
        (location_id,),
    ).fetchone()
    conn.commit()
    conn.close()
    return dict(row)


@app.get("/analytics/map", dependencies=[Depends(verify_api_key)])
def get_map_points(days: int = Query(default=7, ge=1, le=30), min_ors: float = Query(default=60.0)):
    conn = get_connection()
    protected = conn.execute(
        """SELECT id, name, type, lat, lon, radius_miles
        FROM protected_locations
        WHERE active = 1 AND lat IS NOT NULL AND lon IS NOT NULL"""
    ).fetchall()
    alerts = conn.execute(
        """SELECT a.id, a.title, a.ors_score, a.tas_score, a.severity,
                  al.location_text, al.lat, al.lon
        FROM alerts a
        JOIN alert_locations al ON al.alert_id = a.id
        WHERE datetime(COALESCE(a.published_at, a.created_at)) >= datetime('now', ?)
          AND COALESCE(a.ors_score, a.risk_score) >= ?
          AND al.lat IS NOT NULL AND al.lon IS NOT NULL
        ORDER BY COALESCE(a.ors_score, a.risk_score) DESC""",
        (f"-{int(days)} days", float(min_ors)),
    ).fetchall()
    conn.close()
    return {
        "protected_locations": [dict(row) for row in protected],
        "alerts": [dict(row) for row in alerts],
    }


@app.post("/briefs/travel", dependencies=[Depends(verify_api_key)])
def create_travel_brief(body: TravelBriefRequest):
    from analytics.travel_brief import generate_travel_brief

    return generate_travel_brief(
        destination=body.destination,
        start_dt=body.start_dt,
        end_dt=body.end_dt,
        poi_id=body.poi_id,
        protected_location_id=body.protected_location_id,
        persist=True,
    )


@app.get("/briefs/travel", dependencies=[Depends(verify_api_key)])
def list_travel_briefs(limit: int = Query(default=20, ge=1, le=100)):
    conn = get_connection()
    rows = conn.execute(
        """SELECT id, destination, start_dt, end_dt, created_at
        FROM travel_briefs
        ORDER BY created_at DESC
        LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.post("/alerts/{alert_id}/disposition", dependencies=[Depends(verify_api_key)])
def create_disposition(alert_id: int, body: DispositionRequest):
    conn = get_connection()
    alert = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")
    conn.execute(
        """INSERT INTO dispositions
        (alert_id, status, rationale, user, created_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
        (alert_id, body.status.strip(), body.rationale, body.user),
    )
    disposition_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    row = conn.execute("SELECT * FROM dispositions WHERE id = ?", (disposition_id,)).fetchone()
    conn.commit()
    conn.close()
    return dict(row)


# --- KEYWORDS ---


@app.get("/keywords", dependencies=[Depends(verify_api_key)])
def get_keywords():
    conn = get_connection()
    keywords = conn.execute("SELECT * FROM keywords ORDER BY category, term").fetchall()
    conn.close()
    return [dict(k) for k in keywords]


@app.post("/keywords", dependencies=[Depends(verify_api_key)])
def add_keyword(keyword: KeywordCreate):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO keywords (term, category, weight) VALUES (?, ?, ?)",
            (keyword.term, keyword.category, keyword.weight),
        )
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(status_code=409, detail="Keyword already exists")
    new_keyword = conn.execute("SELECT * FROM keywords WHERE term = ?", (keyword.term,)).fetchone()
    conn.close()
    return dict(new_keyword)


@app.delete("/keywords/{keyword_id}", dependencies=[Depends(verify_api_key)])
def delete_keyword(keyword_id: int):
    conn = get_connection()
    result = conn.execute("DELETE FROM keywords WHERE id = ?", (keyword_id,))
    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Keyword not found")
    conn.commit()
    conn.close()
    return {"status": "deleted", "keyword_id": keyword_id}


@app.patch("/keywords/{keyword_id}/weight", dependencies=[Depends(verify_api_key)])
def update_keyword_weight(keyword_id: int, weight: float = Query(ge=0.1, le=5.0)):
    """Update a keyword's threat weight."""
    conn = get_connection()
    result = conn.execute(
        "UPDATE keywords SET weight = ? WHERE id = ?",
        (weight, keyword_id),
    )
    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Keyword not found")
    conn.commit()
    conn.close()
    return {"status": "updated", "keyword_id": keyword_id, "weight": weight}


# --- SOURCES ---


@app.get("/sources", dependencies=[Depends(verify_api_key)])
def get_sources():
    conn = get_connection()
    sources = conn.execute("SELECT * FROM sources ORDER BY source_type, name").fetchall()
    conn.close()
    return [dict(s) for s in sources]


@app.patch("/sources/{source_id}/credibility", dependencies=[Depends(verify_api_key)])
def update_source_credibility(source_id: int, credibility_score: float = Query(ge=0.0, le=1.0)):
    """Update a source's credibility score."""
    conn = get_connection()
    result = conn.execute(
        "UPDATE sources SET credibility_score = ? WHERE id = ?",
        (credibility_score, source_id),
    )
    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Source not found")
    conn.commit()
    conn.close()
    return {"status": "updated", "source_id": source_id, "credibility_score": credibility_score}


# --- THREAT ACTORS ---


@app.get("/threat-actors", dependencies=[Depends(verify_api_key)])
def get_threat_actors():
    conn = get_connection()
    actors = conn.execute("SELECT * FROM threat_actors ORDER BY name").fetchall()
    conn.close()
    return [dict(a) for a in actors]


# --- THREAT SUBJECTS (Behavioral Assessment) ---


class ThreatSubjectCreate(BaseModel):
    name: str
    aliases: list[str] = []
    linked_poi_id: Optional[int] = None
    notes: Optional[str] = None


class ThreatSubjectAssessmentCreate(BaseModel):
    grievance_level: float = 0.0
    fixation_level: float = 0.0
    identification_level: float = 0.0
    novel_aggression: float = 0.0
    energy_burst: float = 0.0
    leakage: float = 0.0
    last_resort: float = 0.0
    directly_communicated_threat: float = 0.0
    evidence_summary: Optional[str] = None
    source_alert_ids: list[int] = []
    analyst_notes: Optional[str] = None


@app.get("/threat-subjects", dependencies=[Depends(verify_api_key)])
def get_threat_subjects(
    status: Optional[str] = Query(default=None),
    min_score: float = Query(default=0.0, ge=0.0, le=100.0),
):
    """List all threat subjects with their latest pathway score."""
    from analytics.behavioral_assessment import get_active_subjects

    conn = get_connection()
    if status and status != "active":
        # get_active_subjects only returns active; for other statuses, query directly
        rows = conn.execute(
            "SELECT * FROM threat_subjects WHERE status = ? ORDER BY name",
            (status,),
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    subjects = get_active_subjects(conn, min_score=min_score)
    conn.close()
    return subjects


@app.post("/threat-subjects", dependencies=[Depends(verify_api_key)])
def create_threat_subject(body: ThreatSubjectCreate):
    """Register a new threat subject for behavioral tracking."""
    conn = get_connection()

    if body.linked_poi_id is not None:
        poi = conn.execute("SELECT id FROM pois WHERE id = ?", (body.linked_poi_id,)).fetchone()
        if not poi:
            conn.close()
            raise HTTPException(status_code=400, detail="Linked POI not found")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """INSERT INTO threat_subjects
        (name, aliases, linked_poi_id, first_seen, last_seen, status, risk_tier, notes)
        VALUES (?, ?, ?, ?, ?, 'active', 'LOW', ?)""",
        (
            body.name.strip(),
            json.dumps([a.strip() for a in body.aliases if a.strip()]),
            body.linked_poi_id,
            now,
            now,
            body.notes,
        ),
    )
    subject_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    row = conn.execute("SELECT * FROM threat_subjects WHERE id = ?", (subject_id,)).fetchone()
    conn.close()
    return dict(row)


@app.get("/threat-subjects/{subject_id}", dependencies=[Depends(verify_api_key)])
def get_threat_subject(subject_id: int):
    """Get a single threat subject with assessment history."""
    from analytics.behavioral_assessment import get_subject_history

    conn = get_connection()
    subject = conn.execute(
        "SELECT * FROM threat_subjects WHERE id = ?",
        (subject_id,),
    ).fetchone()
    if not subject:
        conn.close()
        raise HTTPException(status_code=404, detail="Threat subject not found")

    history = get_subject_history(conn, subject_id, limit=10)
    conn.close()
    result = dict(subject)
    result["assessment_history"] = history
    return result


@app.post("/threat-subjects/{subject_id}/assess", dependencies=[Depends(verify_api_key)])
def assess_threat_subject(subject_id: int, body: ThreatSubjectAssessmentCreate):
    """Submit a behavioral assessment for a threat subject."""
    from analytics.behavioral_assessment import upsert_assessment

    conn = get_connection()
    subject = conn.execute(
        "SELECT id FROM threat_subjects WHERE id = ?",
        (subject_id,),
    ).fetchone()
    if not subject:
        conn.close()
        raise HTTPException(status_code=404, detail="Threat subject not found")

    indicators = {
        "grievance_level": body.grievance_level,
        "fixation_level": body.fixation_level,
        "identification_level": body.identification_level,
        "novel_aggression": body.novel_aggression,
        "energy_burst": body.energy_burst,
        "leakage": body.leakage,
        "last_resort": body.last_resort,
        "directly_communicated_threat": body.directly_communicated_threat,
    }

    result = upsert_assessment(
        conn,
        subject_id,
        indicators,
        evidence_summary=body.evidence_summary,
        source_alert_ids=body.source_alert_ids,
        analyst_notes=body.analyst_notes,
    )
    conn.commit()
    conn.close()
    return result


@app.get("/threat-subjects/{subject_id}/history", dependencies=[Depends(verify_api_key)])
def get_threat_subject_history(
    subject_id: int,
    limit: int = Query(default=20, ge=1, le=100),
):
    """Get longitudinal assessment history for a threat subject."""
    from analytics.behavioral_assessment import get_subject_history

    conn = get_connection()
    subject = conn.execute(
        "SELECT id FROM threat_subjects WHERE id = ?",
        (subject_id,),
    ).fetchone()
    if not subject:
        conn.close()
        raise HTTPException(status_code=404, detail="Threat subject not found")

    history = get_subject_history(conn, subject_id, limit=limit)
    conn.close()
    return history


# --- SITREPs ---


@app.get("/sitreps", dependencies=[Depends(verify_api_key)])
def get_sitreps(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
):
    """List recent SITREPs."""
    from analytics.sitrep import list_sitreps

    conn = get_connection()
    results = list_sitreps(conn, status=status, limit=limit)
    conn.close()
    return results


@app.get("/sitreps/{sitrep_id}", dependencies=[Depends(verify_api_key)])
def get_sitrep(sitrep_id: int):
    """Get a single SITREP by ID."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM sitreps WHERE id = ?", (sitrep_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="SITREP not found")
    result = dict(row)
    for field in ("affected_protectees", "affected_locations", "recommended_actions", "escalation_notify"):
        if result.get(field):
            try:
                result[field] = json.loads(result[field])
            except (json.JSONDecodeError, TypeError):
                pass
    return result


@app.post("/sitreps/generate/poi/{poi_id}", dependencies=[Depends(verify_api_key)])
def generate_poi_sitrep(poi_id: int):
    """Generate a SITREP for a POI based on their current assessment."""
    from analytics.sitrep import generate_sitrep_for_poi_escalation
    from analytics.tas_assessment import compute_poi_assessment

    conn = get_connection()
    poi = conn.execute("SELECT id FROM pois WHERE id = ?", (poi_id,)).fetchone()
    if not poi:
        conn.close()
        raise HTTPException(status_code=404, detail="POI not found")

    assessment = compute_poi_assessment(conn, poi_id, window_days=14)
    if not assessment:
        conn.close()
        raise HTTPException(status_code=404, detail="No assessment data available for this POI")

    sitrep = generate_sitrep_for_poi_escalation(conn, poi_id, assessment)
    conn.commit()
    conn.close()
    if not sitrep:
        raise HTTPException(status_code=500, detail="Failed to generate SITREP")
    return sitrep


@app.post("/sitreps/generate/facility/{location_id}/alert/{alert_id}", dependencies=[Depends(verify_api_key)])
def generate_facility_sitrep(location_id: int, alert_id: int):
    """Generate a SITREP for a facility breach event."""
    from analytics.sitrep import generate_sitrep_for_facility_breach

    conn = get_connection()
    location = conn.execute(
        "SELECT id FROM protected_locations WHERE id = ?",
        (location_id,),
    ).fetchone()
    if not location:
        conn.close()
        raise HTTPException(status_code=404, detail="Protected location not found")

    alert = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    sitrep = generate_sitrep_for_facility_breach(conn, alert_id, location_id)
    conn.commit()
    conn.close()
    if not sitrep:
        raise HTTPException(status_code=500, detail="Failed to generate SITREP")
    return sitrep


@app.patch("/sitreps/{sitrep_id}/issue", dependencies=[Depends(verify_api_key)])
def issue_sitrep_endpoint(sitrep_id: int):
    """Mark a SITREP as issued (distributed up the chain)."""
    from analytics.sitrep import issue_sitrep

    conn = get_connection()
    existing = conn.execute("SELECT id, status FROM sitreps WHERE id = ?", (sitrep_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="SITREP not found")

    row = issue_sitrep(conn, sitrep_id)
    conn.commit()
    conn.close()
    return dict(row)


# --- SOCIAL MEDIA MONITORING ---


@app.post("/scrape/social-media", dependencies=[Depends(verify_api_key)])
def trigger_social_media_scrape():
    """Trigger a social media monitoring run (stub: loads fixture data in demo mode)."""
    from scraper.social_media_monitor import run_social_media_monitor

    result = run_social_media_monitor()
    return result


@app.get("/analytics/escalation-tiers", dependencies=[Depends(verify_api_key)])
def get_escalation_tiers():
    """Return the configured escalation tier thresholds."""
    from database.init_db import load_watchlist_yaml

    watchlist = load_watchlist_yaml()
    if watchlist and watchlist.get("escalation_tiers"):
        return {"tiers": watchlist["escalation_tiers"]}
    # Hardcoded fallback
    return {
        "tiers": [
            {"threshold": 85, "label": "CRITICAL", "notify": ["detail_leader", "intel_manager"],
             "action": "Immediate briefing required.", "response_window": "30 minutes"},
            {"threshold": 65, "label": "ELEVATED", "notify": ["intel_analyst"],
             "action": "Enhanced monitoring. Assess within 4 hours.", "response_window": "4 hours"},
            {"threshold": 40, "label": "ROUTINE", "notify": [],
             "action": "Log and monitor.", "response_window": "24 hours"},
            {"threshold": 0, "label": "LOW", "notify": [],
             "action": "No immediate action.", "response_window": "N/A"},
        ]
    }
