"""
Backtesting Framework — Golden Dataset Validation.

Compares the multi-factor scoring engine against a naive baseline using
protective-intelligence scenarios. Validates that the full scoring model
(keyword weight x frequency factor x source credibility x recency)
outperforms simple keyword weight alone.

Baseline:  score = keyword_weight x 20 (no frequency, no credibility, no recency)
Full model: compute_risk_score() with source credibility, frequency, and recency context.
"""

from analytics.risk_scoring import compute_risk_score, score_to_severity

# Golden dataset: EP scenarios with expected severity outcomes.
# Initial benchmark (n=35). Expand with operational case studies as available.
GOLDEN_DATASET = [
    # --- CRITICAL (direct targeting, imminent, high-credibility) ---
    {
        "name": "Direct Threat to CEO Before Town Hall",
        "keyword": "death threat",
        "keyword_weight": 4.8,
        "expected_severity": "critical",
        "source_credibility": 0.95,
        "frequency_factor": 2.2,
        "recency_hours": 2.0,
        "description": "Named death threat references upcoming executive appearance at quarterly town hall event.",
    },
    {
        "name": "Doxxing Post with Residential Address",
        "keyword": "doxxing",
        "keyword_weight": 4.6,
        "expected_severity": "critical",
        "source_credibility": 0.75,
        "frequency_factor": 1.5,
        "recency_hours": 3.0,
        "description": "Address disclosure and targeting language against protectee posted on public forum.",
    },
    {
        "name": "Fixated Individual Approaches HQ with Weapon",
        "keyword": "armed approach",
        "keyword_weight": 5.0,
        "expected_severity": "critical",
        "source_credibility": 0.98,
        "frequency_factor": 3.0,
        "recency_hours": 0.5,
        "description": "Security reports armed individual at perimeter matching prior threat subject profile.",
    },
    {
        "name": "Credible Kidnapping Threat During Overseas Travel",
        "keyword": "kidnapping",
        "keyword_weight": 4.9,
        "expected_severity": "critical",
        "source_credibility": 0.85,
        "frequency_factor": 2.0,
        "recency_hours": 1.5,
        "description": "Specific kidnap-for-ransom threat naming protectee and hotel location during active trip.",
    },
    {
        "name": "Coordinated Harassment Campaign with Home Address",
        "keyword": "doxxing",
        "keyword_weight": 4.6,
        "expected_severity": "critical",
        "source_credibility": 0.88,
        "frequency_factor": 2.5,
        "recency_hours": 1.0,
        "description": "Multiple forums coordinate harassment campaign sharing protectee home address and family photos.",
    },
    # --- HIGH (credible threat, elevated risk, operational concern) ---
    {
        "name": "Swatting Call to Headquarters",
        "keyword": "swatting",
        "keyword_weight": 3.8,
        "expected_severity": "high",
        "source_credibility": 0.7,
        "frequency_factor": 1.3,
        "recency_hours": 4.0,
        "description": "Credible swatting incident targeting HQ switchboard during business hours.",
    },
    {
        "name": "Suspicious Drone Near Residence",
        "keyword": "drone surveillance",
        "keyword_weight": 3.4,
        "expected_severity": "high",
        "source_credibility": 0.55,
        "frequency_factor": 1.2,
        "recency_hours": 6.0,
        "description": "Single-source drone observation near protectee residence reported by security detail.",
    },
    {
        "name": "Violent Rhetoric Around Event Protest",
        "keyword": "protest violence",
        "keyword_weight": 3.6,
        "expected_severity": "high",
        "source_credibility": 0.8,
        "frequency_factor": 1.3,
        "recency_hours": 8.0,
        "description": "Escalating protest chatter includes explicit disruption intent near event venue.",
    },
    {
        "name": "State Dept Level 3 at Planned Destination",
        "keyword": "travel advisory level 3",
        "keyword_weight": 3.0,
        "expected_severity": "high",
        "source_credibility": 0.9,
        "frequency_factor": 1.4,
        "recency_hours": 12.0,
        "description": "Destination reconsider-travel advisory issued while executive travel is planned.",
    },
    {
        "name": "Anonymous Bomb Threat, Low Credibility Source",
        "keyword": "bomb threat",
        "keyword_weight": 4.5,
        "expected_severity": "high",
        "source_credibility": 0.35,
        "frequency_factor": 1.0,
        "recency_hours": 2.0,
        "description": "Single low-confidence threat email referencing HQ building with no corroboration.",
    },
    {
        "name": "Insider Grievance with Target Date",
        "keyword": "workplace violence",
        "keyword_weight": 4.0,
        "expected_severity": "high",
        "source_credibility": 0.7,
        "frequency_factor": 1.4,
        "recency_hours": 5.0,
        "description": "Identified insider expresses grievance and states intent for specific date.",
    },
    {
        "name": "Hostile Surveillance Report at Event Venue",
        "keyword": "hostile surveillance",
        "keyword_weight": 4.2,
        "expected_severity": "high",
        "source_credibility": 0.65,
        "frequency_factor": 1.1,
        "recency_hours": 3.0,
        "description": "Advance team reports individual conducting counter-surveillance at conference venue.",
    },
    {
        "name": "Extremist Forum Names Protectee as Target",
        "keyword": "targeting",
        "keyword_weight": 4.4,
        "expected_severity": "high",
        "source_credibility": 0.6,
        "frequency_factor": 1.6,
        "recency_hours": 8.0,
        "description": "Extremist forum thread explicitly names protectee and discusses route patterns.",
    },
    {
        "name": "Vehicle Tampering Near Executive Parking",
        "keyword": "sabotage",
        "keyword_weight": 4.3,
        "expected_severity": "high",
        "source_credibility": 0.72,
        "frequency_factor": 1.0,
        "recency_hours": 2.0,
        "description": "Security camera captures unauthorized individual near executive vehicles after hours.",
    },
    {
        "name": "Stalking Behavior Escalation with Leakage",
        "keyword": "stalking",
        "keyword_weight": 4.1,
        "expected_severity": "high",
        "source_credibility": 0.68,
        "frequency_factor": 1.8,
        "recency_hours": 6.0,
        "description": "Known fixated individual posts timeline and plan to approach protectee at public event.",
    },
    {
        "name": "State Dept Level 4 Do Not Travel Alert",
        "keyword": "travel advisory level 4",
        "keyword_weight": 3.2,
        "expected_severity": "high",
        "source_credibility": 0.95,
        "frequency_factor": 1.5,
        "recency_hours": 4.0,
        "description": "Do-not-travel advisory for country on executive itinerary due to armed conflict.",
    },
    # --- MEDIUM (monitor, moderate risk, non-imminent) ---
    {
        "name": "Protest Planned Near Office, Moderate Rhetoric",
        "keyword": "protest",
        "keyword_weight": 3.2,
        "expected_severity": "medium",
        "source_credibility": 0.65,
        "frequency_factor": 1.3,
        "recency_hours": 14.0,
        "description": "Permitted protest planned within half mile of office with some aggressive rhetoric.",
    },
    {
        "name": "Civil Unrest in Travel Destination City",
        "keyword": "civil unrest",
        "keyword_weight": 2.8,
        "expected_severity": "medium",
        "source_credibility": 0.75,
        "frequency_factor": 1.5,
        "recency_hours": 10.0,
        "description": "Ongoing civil unrest reported in city where protectee has travel scheduled next week.",
    },
    {
        "name": "Online Harassment Campaign Against Company",
        "keyword": "harassment",
        "keyword_weight": 3.0,
        "expected_severity": "medium",
        "source_credibility": 0.55,
        "frequency_factor": 1.4,
        "recency_hours": 12.0,
        "description": "Organized online harassment targeting company brand with some executive name mentions.",
    },
    {
        "name": "Former Employee Venting on Social Media",
        "keyword": "workplace grievance",
        "keyword_weight": 3.0,
        "expected_severity": "medium",
        "source_credibility": 0.5,
        "frequency_factor": 1.1,
        "recency_hours": 8.0,
        "description": "Recently terminated employee posts angry messages about company leadership on social media.",
    },
    {
        "name": "Suspicious Package Protocol at Regional Office",
        "keyword": "suspicious package",
        "keyword_weight": 3.5,
        "expected_severity": "medium",
        "source_credibility": 0.6,
        "frequency_factor": 1.0,
        "recency_hours": 3.0,
        "description": "Mailroom flags unidentified package at regional office; no protectee on site.",
    },
    {
        "name": "State Dept Level 2 Advisory Update",
        "keyword": "travel advisory level 2",
        "keyword_weight": 2.5,
        "expected_severity": "medium",
        "source_credibility": 0.9,
        "frequency_factor": 1.2,
        "recency_hours": 18.0,
        "description": "Exercise-increased-caution advisory for destination on upcoming executive trip.",
    },
    {
        "name": "Keyword Spike for Protectee Name, No Threat Context",
        "keyword": "executive mention",
        "keyword_weight": 3.5,
        "expected_severity": "medium",
        "source_credibility": 0.5,
        "frequency_factor": 2.0,
        "recency_hours": 6.0,
        "description": "Unusual spike in protectee name mentions across news and social media after earnings call.",
    },
    # --- LOW (routine, no threat, informational) ---
    {
        "name": "Permitted Demonstration, No Threat Language",
        "keyword": "protest",
        "keyword_weight": 3.2,
        "expected_severity": "low",
        "source_credibility": 0.5,
        "frequency_factor": 0.9,
        "recency_hours": 18.0,
        "description": "Routine permitted rally with no violent indicators and no proximity to assets.",
    },
    {
        "name": "Local Pickpocket Advisory",
        "keyword": "petty crime",
        "keyword_weight": 2.0,
        "expected_severity": "low",
        "source_credibility": 0.8,
        "frequency_factor": 1.1,
        "recency_hours": 24.0,
        "description": "General petty crime guidance for travel destination with no protectee targeting.",
    },
    {
        "name": "Vague Social Mention of Executive Schedule",
        "keyword": "executive mention",
        "keyword_weight": 3.5,
        "expected_severity": "low",
        "source_credibility": 0.3,
        "frequency_factor": 0.8,
        "recency_hours": 4.0,
        "description": "Unverified chatter with no direct threat language or location specifics.",
    },
    {
        "name": "Rumor of Disruption, No Corroboration",
        "keyword": "possible disruption",
        "keyword_weight": 3.6,
        "expected_severity": "low",
        "source_credibility": 0.25,
        "frequency_factor": 0.8,
        "recency_hours": 10.0,
        "description": "Low-confidence rumor with no supporting operational evidence from single anonymous post.",
    },
    {
        "name": "Satirical Post Reposting Aggressive Language",
        "keyword": "violent rhetoric",
        "keyword_weight": 3.7,
        "expected_severity": "low",
        "source_credibility": 0.2,
        "frequency_factor": 0.7,
        "recency_hours": 36.0,
        "description": "Quoted rhetoric with clear satire indicators and no targeting evidence.",
    },
    {
        "name": "News Article Mentions Protectee Positively",
        "keyword": "executive mention",
        "keyword_weight": 3.5,
        "expected_severity": "low",
        "source_credibility": 0.85,
        "frequency_factor": 1.0,
        "recency_hours": 48.0,
        "description": "Business press covers protectee keynote at industry conference with positive framing.",
    },
    {
        "name": "Historical Threat Actor Inactive for 6 Months",
        "keyword": "threat actor",
        "keyword_weight": 3.0,
        "expected_severity": "low",
        "source_credibility": 0.4,
        "frequency_factor": 0.6,
        "recency_hours": 72.0,
        "description": "Previously tracked threat actor with no activity in 180 days mentioned in roundup.",
    },
    {
        "name": "Routine Weather Advisory for Event City",
        "keyword": "weather disruption",
        "keyword_weight": 1.5,
        "expected_severity": "low",
        "source_credibility": 0.9,
        "frequency_factor": 1.0,
        "recency_hours": 20.0,
        "description": "Standard weather advisory for event city with no safety implications.",
    },
    {
        "name": "Generic Anti-Corporate Meme Circulating",
        "keyword": "corporate threat",
        "keyword_weight": 2.2,
        "expected_severity": "low",
        "source_credibility": 0.15,
        "frequency_factor": 0.9,
        "recency_hours": 30.0,
        "description": "Viral meme criticizing tech companies with no specific targeting or threat language.",
    },
    {
        "name": "Old Forum Post Resurfaced by Crawler",
        "keyword": "targeting",
        "keyword_weight": 4.4,
        "expected_severity": "low",
        "source_credibility": 0.2,
        "frequency_factor": 0.5,
        "recency_hours": 120.0,
        "description": "Two-year-old forum post about company resurfaced by scraper with no new activity.",
    },
    {
        "name": "Unrelated Kidnapping Report in Different Country",
        "keyword": "kidnapping",
        "keyword_weight": 4.9,
        "expected_severity": "low",
        "source_credibility": 0.7,
        "frequency_factor": 0.8,
        "recency_hours": 48.0,
        "description": "Kidnapping incident in country with no protectee presence or travel plans.",
    },
    {
        "name": "Academic Paper Citing Company Security Posture",
        "keyword": "security assessment",
        "keyword_weight": 2.0,
        "expected_severity": "low",
        "source_credibility": 0.6,
        "frequency_factor": 0.7,
        "recency_hours": 96.0,
        "description": "Published academic paper references corporate security practices with no operational value.",
    },
]


def run_backtest():
    """
    Run the full scoring model against the golden dataset and compare
    with baseline scoring.

    Returns:
        dict with per-incident results and aggregate metrics
    """
    results = []
    baseline_correct = 0
    full_correct = 0
    baseline_total_score = 0.0
    full_total_score = 0.0

    for incident in GOLDEN_DATASET:
        # Baseline: keyword_weight x 20, no other factors
        baseline_score = round(min(100.0, max(0.0, incident["keyword_weight"] * 20.0)), 1)
        baseline_severity = score_to_severity(baseline_score)

        # Full model: multi-factor scoring
        full_score, full_severity = compute_risk_score(
            keyword_weight=incident["keyword_weight"],
            source_credibility=incident["source_credibility"],
            frequency_factor=incident["frequency_factor"],
            recency_hours=incident["recency_hours"],
        )

        expected = incident["expected_severity"]
        baseline_match = baseline_severity == expected
        full_match = full_severity == expected

        if baseline_match:
            baseline_correct += 1
        if full_match:
            full_correct += 1

        baseline_total_score += baseline_score
        full_total_score += full_score

        results.append(
            {
                "incident": incident["name"],
                "keyword": incident["keyword"],
                "expected_severity": expected,
                "baseline_score": baseline_score,
                "baseline_severity": baseline_severity,
                "baseline_correct": baseline_match,
                "full_score": full_score,
                "full_severity": full_severity,
                "full_correct": full_match,
                "score_improvement": round(full_score - baseline_score, 1),
                "description": incident["description"],
            }
        )

    n = len(GOLDEN_DATASET)
    return {
        "incidents": results,
        "aggregate": {
            "total_incidents": n,
            "baseline_detection_rate": round(baseline_correct / n, 4),
            "full_detection_rate": round(full_correct / n, 4),
            "baseline_correct": baseline_correct,
            "full_correct": full_correct,
            "baseline_mean_score": round(baseline_total_score / n, 1),
            "full_mean_score": round(full_total_score / n, 1),
            "mean_score_improvement": round((full_total_score - baseline_total_score) / n, 1),
        },
    }
