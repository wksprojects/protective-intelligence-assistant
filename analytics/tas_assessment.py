"""TRAP-lite threat assessment scoring for protectees."""

import json
import re
from collections import defaultdict
from datetime import timedelta

import yaml

from analytics.uncertainty import beta_adjusted_interval
from analytics.utils import utcnow
from database.init_db import WATCHLIST_CONFIG_PATH

LEAKAGE_PATTERNS = [
    re.compile(r"\b(i\s+will|we\s+will|going\s+to|plan\s+to|intend\s+to)\b", re.IGNORECASE),
    re.compile(r"\b(tomorrow|tonight|next\s+week|at\s+\d{1,2}(:\d{2})?)\b", re.IGNORECASE),
]
PATHWAY_PATTERNS = [
    re.compile(r"\b(route|entrance|badge|schedule|residence|home address|weapon|gun|rifle)\b", re.IGNORECASE),
    re.compile(r"\b(venue|parking|security gate|access)\b", re.IGNORECASE),
]
TARGETING_TIME_PATTERNS = [
    re.compile(r"\b(on\s+\w+day|at\s+\d{1,2}(:\d{2})?|between\s+\d{1,2})\b", re.IGNORECASE),
    re.compile(r"\b(today|tomorrow|this\s+week|next\s+week)\b", re.IGNORECASE),
]


def _assessment_window_bounds(window_days):
    # Anchor to day boundaries so repeated runs during the same day upsert
    # the same rolling window row.
    now = utcnow()
    window_end_dt = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    window_start_dt = window_end_dt - timedelta(days=window_days)
    return (
        window_start_dt.strftime("%Y-%m-%d %H:%M:%S"),
        window_end_dt.strftime("%Y-%m-%d %H:%M:%S"),
    )


def _compute_energy_burst(day_counts):
    today = utcnow().strftime("%Y-%m-%d")
    today_count = day_counts.get(today, 0)
    baseline_days = sorted(day_counts.keys())[-8:-1]
    baseline = [day_counts[d] for d in baseline_days]
    if len(baseline) < 3:
        return False, 0.0
    mean = sum(baseline) / len(baseline)
    variance = sum((v - mean) ** 2 for v in baseline) / len(baseline)
    std = max(variance**0.5, 0.5)
    z = (today_count - mean) / std
    return z >= 2.0, round(z, 3)


def _source_beta_for_poi(conn, poi_id, window_start, window_end):
    rows = conn.execute(
        """SELECT s.bayesian_alpha, s.bayesian_beta
        FROM poi_hits ph
        JOIN alerts a ON a.id = ph.alert_id
        JOIN sources s ON s.id = a.source_id
        WHERE ph.poi_id = ?
          AND datetime(COALESCE(a.published_at, a.created_at)) >= datetime(?)
          AND datetime(COALESCE(a.published_at, a.created_at)) < datetime(?)""",
        (poi_id, window_start, window_end),
    ).fetchall()
    if not rows:
        return 2.0, 2.0
    alpha = sum(float(row["bayesian_alpha"] or 2.0) for row in rows) / len(rows)
    beta = sum(float(row["bayesian_beta"] or 2.0) for row in rows) / len(rows)
    return max(0.01, alpha), max(0.01, beta)


def compute_poi_assessment(conn, poi_id, window_days=14, n=500):
    window_start, window_end = _assessment_window_bounds(window_days)

    rows = conn.execute(
        """SELECT ph.context, ph.match_value,
                  a.id AS alert_id, a.title, a.content,
                  date(COALESCE(a.published_at, a.created_at)) AS day,
                  EXISTS(SELECT 1 FROM alert_locations al WHERE al.alert_id = a.id) AS has_location
        FROM poi_hits ph
        JOIN alerts a ON a.id = ph.alert_id
        WHERE ph.poi_id = ?
          AND datetime(COALESCE(a.published_at, a.created_at)) >= datetime(?)
          AND datetime(COALESCE(a.published_at, a.created_at)) < datetime(?)
        ORDER BY COALESCE(a.published_at, a.created_at) ASC""",
        (poi_id, window_start, window_end),
    ).fetchall()

    if not rows:
        return None

    day_counts = defaultdict(int)
    leakage = pathway = targeting_specificity = False
    excerpts = []

    for row in rows:
        day_counts[row["day"]] += 1
        text = f"{row['title'] or ''} {row['content'] or ''}"
        if any(pattern.search(text) for pattern in LEAKAGE_PATTERNS):
            leakage = True
        if any(pattern.search(text) for pattern in PATHWAY_PATTERNS):
            pathway = True
        if row["has_location"] and any(pattern.search(text) for pattern in TARGETING_TIME_PATTERNS):
            targeting_specificity = True
        if row["context"] and len(excerpts) < 3:
            excerpts.append(row["context"])

    distinct_days = len(day_counts)
    ordered_days = sorted(day_counts)
    split = max(1, len(ordered_days) // 2)
    first_half = sum(day_counts[d] for d in ordered_days[:split])
    second_half = sum(day_counts[d] for d in ordered_days[split:])
    fixation = distinct_days >= 3 and second_half > first_half

    energy_burst, energy_z = _compute_energy_burst(day_counts)

    tas_score = 0.0
    tas_score += 25.0 if fixation else 0.0
    tas_score += 20.0 if energy_burst else 0.0
    tas_score += 20.0 if leakage else 0.0
    tas_score += 20.0 if pathway else 0.0
    tas_score += 15.0 if targeting_specificity else 0.0
    tas_score = min(100.0, round(tas_score, 3))

    alpha, beta = _source_beta_for_poi(conn, poi_id, window_start, window_end)
    interval = beta_adjusted_interval(base_score=tas_score, alpha=alpha, beta=beta, n=n, seed=poi_id)

    evidence = {
        "window_days": window_days,
        "distinct_days": distinct_days,
        "hits": len(rows),
        "energy_z": energy_z,
        "excerpts": excerpts,
        "interval": interval,
    }

    conn.execute(
        """INSERT INTO poi_assessments
        (poi_id, window_start, window_end, fixation, energy_burst, leakage, pathway,
         targeting_specificity, tas_score, evidence_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(poi_id, window_start, window_end) DO UPDATE SET
            fixation = excluded.fixation,
            energy_burst = excluded.energy_burst,
            leakage = excluded.leakage,
            pathway = excluded.pathway,
            targeting_specificity = excluded.targeting_specificity,
            tas_score = excluded.tas_score,
            evidence_json = excluded.evidence_json,
            created_at = CURRENT_TIMESTAMP""",
        (
            poi_id,
            window_start,
            window_end,
            int(fixation),
            int(energy_burst),
            int(leakage),
            int(pathway),
            int(targeting_specificity),
            tas_score,
            json.dumps(evidence),
        ),
    )

    return {
        "poi_id": poi_id,
        "window_start": window_start,
        "window_end": window_end,
        "fixation": int(fixation),
        "energy_burst": int(energy_burst),
        "leakage": int(leakage),
        "pathway": int(pathway),
        "targeting_specificity": int(targeting_specificity),
        "tas_score": tas_score,
        "evidence": evidence,
    }


FLAG_DESCRIPTIONS = {
    "fixation": "Persistent, recurring attention to the protectee across multiple days — indicates obsessive focus.",
    "energy_burst": "Sudden spike in mention frequency (z ≥ 2.0 vs 7-day baseline) — suggests escalating urgency.",
    "leakage": "Language signaling intent or timeline (e.g., 'tomorrow', 'plan to', 'going to') — pre-attack indicator.",
    "pathway": "References to operational details (routes, entrances, schedules, weapons) — preparation behavior.",
    "targeting_specificity": "Combination of location data + time references — indicates specific targeting window.",
}


def _load_escalation_tiers():
    """Load escalation tier config from watchlist.yaml."""
    try:
        with open(WATCHLIST_CONFIG_PATH, "r") as fh:
            config = yaml.safe_load(fh) or {}
        return config.get("escalation_tiers", [])
    except (OSError, yaml.YAMLError, AttributeError):
        return [
            {"threshold": 85, "label": "CRITICAL", "notify": ["detail_leader", "intel_manager"],
             "action": "Immediate briefing required.", "response_window": "30 minutes"},
            {"threshold": 65, "label": "ELEVATED", "notify": ["intel_analyst"],
             "action": "Enhanced monitoring. Assess within 4 hours.", "response_window": "4 hours"},
            {"threshold": 40, "label": "ROUTINE", "notify": [],
             "action": "Log and monitor.", "response_window": "24 hours"},
            {"threshold": 0, "label": "LOW", "notify": [],
             "action": "No immediate action.", "response_window": "N/A"},
        ]


def _resolve_escalation_tier(score):
    """Map a TAS score to the appropriate escalation tier."""
    tiers = _load_escalation_tiers()
    if not tiers:
        return {"label": "ROUTINE", "notify": [], "action": "Monitor.", "response_window": "24 hours"}
    tiers_sorted = sorted(tiers, key=lambda t: t.get("threshold", 0), reverse=True)
    for tier in tiers_sorted:
        if score >= tier.get("threshold", 0):
            return tier
    return tiers_sorted[-1] if tiers_sorted else {"label": "LOW", "notify": [], "action": "Archive."}


def build_escalation_explanation(assessment):
    """Build an 'Escalate because...' block from a TAS assessment.

    Returns a dict with:
      - escalation_tier (CRITICAL/ELEVATED/ROUTINE/LOW)
      - flags_fired: list of {name, description} for each active TRAP-lite flag
      - evidence_strings: up to 3 text excerpts that informed the assessment
      - recommended_action: what the analyst should do
      - response_window: SLA for the tier
      - notify: list of roles to notify
    """
    tas_score = float(assessment.get("tas_score", 0.0))
    tier = _resolve_escalation_tier(tas_score)

    flags_fired = []
    for flag_name, description in FLAG_DESCRIPTIONS.items():
        if int(assessment.get(flag_name, 0)) == 1:
            flags_fired.append({"flag": flag_name, "description": description})

    evidence = assessment.get("evidence") or {}
    excerpts = evidence.get("excerpts", [])

    actions = [tier.get("action", "Monitor.")]
    if tas_score >= 65:
        actions.append("Review all POI hits for the assessment window.")
        actions.append("Verify protectee's current location and upcoming movements.")
    if tas_score >= 85:
        actions.insert(0, "IMMEDIATE: Brief detail leader and intel manager.")
        actions.append("Consider enhanced protective posture.")

    return {
        "escalation_tier": tier.get("label", "ROUTINE"),
        "flags_fired": flags_fired,
        "evidence_strings": excerpts[:3],
        "recommended_actions": actions,
        "response_window": tier.get("response_window", "N/A"),
        "notify": tier.get("notify", []),
        "summary": _build_escalation_summary(tas_score, flags_fired, evidence, tier),
    }


def _build_escalation_summary(tas_score, flags_fired, evidence, tier):
    """One-paragraph human-readable escalation summary."""
    if not flags_fired:
        return f"TAS {tas_score:.1f} — No TRAP-lite flags active. {tier.get('action', 'Monitor.')}."

    flag_names = [f["flag"].replace("_", " ") for f in flags_fired]
    hit_count = evidence.get("hits", 0)
    day_count = evidence.get("distinct_days", 0)

    summary = (
        f"Escalate: TAS {tas_score:.1f} ({tier.get('label', 'ROUTINE')}). "
        f"TRAP-lite flags: {', '.join(flag_names)}. "
        f"{hit_count} hit(s) across {day_count} day(s). "
    )
    if tier.get("response_window"):
        summary += f"Response window: {tier['response_window']}."
    return summary


def update_alert_tas(conn, alert_id):
    poi_rows = conn.execute(
        "SELECT DISTINCT poi_id FROM poi_hits WHERE alert_id = ?",
        (alert_id,),
    ).fetchall()
    if not poi_rows:
        conn.execute("UPDATE alerts SET tas_score = 0.0 WHERE id = ?", (alert_id,))
        return {"alert_id": alert_id, "tas_score": 0.0, "pois": []}

    assessments = []
    for row in poi_rows:
        assessment = compute_poi_assessment(conn, row["poi_id"], window_days=14)
        if assessment:
            assessments.append(assessment)

    tas_score = max((a["tas_score"] for a in assessments), default=0.0)
    conn.execute("UPDATE alerts SET tas_score = ? WHERE id = ?", (float(tas_score), alert_id))
    return {
        "alert_id": alert_id,
        "tas_score": float(tas_score),
        "pois": assessments,
    }
