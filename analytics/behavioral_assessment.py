"""Behavioral threat assessment for threat subjects (pathway-to-violence model)."""

import json
from datetime import timedelta

from analytics.utils import utcnow


# Pathway indicator weights for composite score (sum to 1.0)
PATHWAY_WEIGHTS = {
    "grievance_level": 0.10,
    "fixation_level": 0.15,
    "identification_level": 0.10,
    "novel_aggression": 0.15,
    "energy_burst": 0.10,
    "leakage": 0.15,
    "last_resort": 0.10,
    "directly_communicated_threat": 0.15,
}

INDICATOR_NAMES = list(PATHWAY_WEIGHTS.keys())


def compute_pathway_score(indicators: dict) -> float:
    """Compute weighted pathway-to-violence composite score (0-100)."""
    score = 0.0
    for indicator, weight in PATHWAY_WEIGHTS.items():
        value = float(indicators.get(indicator, 0.0))
        value = max(0.0, min(1.0, value))
        score += value * weight * 100.0
    return round(min(100.0, max(0.0, score)), 3)


def determine_escalation_trend(conn, subject_id, current_score, lookback_days=30):
    """Compare current assessment to recent history to determine trend."""
    cutoff = (utcnow() - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
    rows = conn.execute(
        """SELECT pathway_score FROM threat_subject_assessments
        WHERE subject_id = ? AND assessment_date >= ?
        ORDER BY assessment_date DESC
        LIMIT 5""",
        (subject_id, cutoff),
    ).fetchall()

    if len(rows) < 2:
        return "stable"

    previous_scores = [float(row["pathway_score"]) for row in rows]
    avg_previous = sum(previous_scores) / len(previous_scores)

    if current_score > avg_previous + 5.0:
        return "increasing"
    elif current_score < avg_previous - 5.0:
        return "decreasing"
    return "stable"


def score_to_risk_tier(pathway_score):
    """Map pathway score to risk tier."""
    if pathway_score >= 75:
        return "CRITICAL"
    elif pathway_score >= 50:
        return "ELEVATED"
    elif pathway_score >= 25:
        return "ROUTINE"
    return "LOW"


def upsert_assessment(conn, subject_id, indicators, evidence_summary=None,
                      source_alert_ids=None, analyst_notes=None):
    """Create or update a behavioral assessment for a threat subject."""
    pathway_score = compute_pathway_score(indicators)
    escalation_trend = determine_escalation_trend(conn, subject_id, pathway_score)
    risk_tier = score_to_risk_tier(pathway_score)
    assessment_date = utcnow().strftime("%Y-%m-%d")

    conn.execute(
        """INSERT INTO threat_subject_assessments
        (subject_id, assessment_date, grievance_level, fixation_level,
         identification_level, novel_aggression, energy_burst, leakage,
         last_resort, directly_communicated_threat,
         pathway_score, escalation_trend, evidence_summary,
         source_alert_ids, analyst_notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(subject_id, assessment_date) DO UPDATE SET
            grievance_level = excluded.grievance_level,
            fixation_level = excluded.fixation_level,
            identification_level = excluded.identification_level,
            novel_aggression = excluded.novel_aggression,
            energy_burst = excluded.energy_burst,
            leakage = excluded.leakage,
            last_resort = excluded.last_resort,
            directly_communicated_threat = excluded.directly_communicated_threat,
            pathway_score = excluded.pathway_score,
            escalation_trend = excluded.escalation_trend,
            evidence_summary = excluded.evidence_summary,
            source_alert_ids = excluded.source_alert_ids,
            analyst_notes = excluded.analyst_notes""",
        (
            subject_id,
            assessment_date,
            float(indicators.get("grievance_level", 0.0)),
            float(indicators.get("fixation_level", 0.0)),
            float(indicators.get("identification_level", 0.0)),
            float(indicators.get("novel_aggression", 0.0)),
            float(indicators.get("energy_burst", 0.0)),
            float(indicators.get("leakage", 0.0)),
            float(indicators.get("last_resort", 0.0)),
            float(indicators.get("directly_communicated_threat", 0.0)),
            pathway_score,
            escalation_trend,
            evidence_summary,
            json.dumps(source_alert_ids or []),
            analyst_notes,
        ),
    )

    # Update subject risk tier and last_seen
    conn.execute(
        """UPDATE threat_subjects
        SET risk_tier = ?, last_seen = ?, status = 'active'
        WHERE id = ?""",
        (risk_tier, utcnow().strftime("%Y-%m-%d %H:%M:%S"), subject_id),
    )

    return {
        "subject_id": subject_id,
        "assessment_date": assessment_date,
        "pathway_score": pathway_score,
        "escalation_trend": escalation_trend,
        "risk_tier": risk_tier,
        "indicators": {k: float(indicators.get(k, 0.0)) for k in INDICATOR_NAMES},
    }


def get_subject_history(conn, subject_id, limit=20):
    """Get assessment history for a threat subject."""
    rows = conn.execute(
        """SELECT * FROM threat_subject_assessments
        WHERE subject_id = ?
        ORDER BY assessment_date DESC
        LIMIT ?""",
        (subject_id, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def get_active_subjects(conn, min_score=0.0):
    """Get all active threat subjects with their latest assessment."""
    subjects = conn.execute(
        """SELECT ts.*,
                  tsa.pathway_score AS latest_pathway_score,
                  tsa.escalation_trend AS latest_trend,
                  tsa.assessment_date AS latest_assessment_date
        FROM threat_subjects ts
        LEFT JOIN threat_subject_assessments tsa ON tsa.id = (
            SELECT id FROM threat_subject_assessments
            WHERE subject_id = ts.id
            ORDER BY assessment_date DESC LIMIT 1
        )
        WHERE ts.status = 'active'
          AND COALESCE(tsa.pathway_score, 0.0) >= ?
        ORDER BY COALESCE(tsa.pathway_score, 0.0) DESC""",
        (float(min_score),),
    ).fetchall()
    return [dict(row) for row in subjects]
