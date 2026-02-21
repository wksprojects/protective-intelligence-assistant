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
GOLDEN_DATASET = [
    {
        "name": "Direct Threat to CEO Before Town Hall",
        "keyword": "death threat",
        "keyword_weight": 4.8,
        "expected_severity": "critical",
        "source_credibility": 0.95,
        "frequency_factor": 2.2,
        "recency_hours": 2.0,
        "description": "Named death threat references upcoming executive appearance.",
    },
    {
        "name": "Swatting Call to Headquarters",
        "keyword": "swatting",
        "keyword_weight": 3.8,
        "expected_severity": "high",
        "source_credibility": 0.7,
        "frequency_factor": 1.3,
        "recency_hours": 4.0,
        "description": "Credible swatting incident targeting HQ switchboard.",
    },
    {
        "name": "Suspicious Drone Near Residence",
        "keyword": "drone surveillance",
        "keyword_weight": 3.4,
        "expected_severity": "high",
        "source_credibility": 0.55,
        "frequency_factor": 1.2,
        "recency_hours": 6.0,
        "description": "Single-source drone observation near protectee residence.",
    },
    {
        "name": "Violent Rhetoric Around Event Protest",
        "keyword": "protest violence",
        "keyword_weight": 3.6,
        "expected_severity": "high",
        "source_credibility": 0.8,
        "frequency_factor": 1.3,
        "recency_hours": 8.0,
        "description": "Escalating protest chatter includes explicit disruption intent.",
    },
    {
        "name": "Permitted Demonstration, No Threat Language",
        "keyword": "protest",
        "keyword_weight": 3.2,
        "expected_severity": "low",
        "source_credibility": 0.5,
        "frequency_factor": 0.9,
        "recency_hours": 18.0,
        "description": "Routine permitted rally with no violent indicators.",
    },
    {
        "name": "State Dept Level 3 at Planned Destination",
        "keyword": "travel advisory level 3",
        "keyword_weight": 3.0,
        "expected_severity": "high",
        "source_credibility": 0.9,
        "frequency_factor": 1.4,
        "recency_hours": 12.0,
        "description": "Destination advisory increases travel risk for planned movement.",
    },
    {
        "name": "Local Pickpocket Advisory",
        "keyword": "petty crime",
        "keyword_weight": 2.0,
        "expected_severity": "low",
        "source_credibility": 0.8,
        "frequency_factor": 1.1,
        "recency_hours": 24.0,
        "description": "General petty crime guidance with no protectee targeting.",
    },
    {
        "name": "Vague Social Mention of Executive Schedule",
        "keyword": "executive mention",
        "keyword_weight": 3.5,
        "expected_severity": "low",
        "source_credibility": 0.3,
        "frequency_factor": 0.8,
        "recency_hours": 4.0,
        "description": "Unverified chatter, no direct threat or location specifics.",
    },
    {
        "name": "Doxxing Post with Residential Address",
        "keyword": "doxxing",
        "keyword_weight": 4.6,
        "expected_severity": "critical",
        "source_credibility": 0.75,
        "frequency_factor": 1.5,
        "recency_hours": 3.0,
        "description": "Address disclosure and targeting language against protectee.",
    },
    {
        "name": "Anonymous Bomb Threat, Low Credibility Source",
        "keyword": "bomb threat",
        "keyword_weight": 4.5,
        "expected_severity": "high",
        "source_credibility": 0.35,
        "frequency_factor": 1.0,
        "recency_hours": 2.0,
        "description": "Single low-confidence threat email with no corroboration.",
    },
    {
        "name": "Insider Grievance with Target Date",
        "keyword": "workplace violence",
        "keyword_weight": 4.0,
        "expected_severity": "high",
        "source_credibility": 0.7,
        "frequency_factor": 1.4,
        "recency_hours": 5.0,
        "description": "Identified insider expresses grievance and time-bound intent.",
    },
    {
        "name": "Rumor of Disruption, No Corroboration",
        "keyword": "possible disruption",
        "keyword_weight": 3.6,
        "expected_severity": "low",
        "source_credibility": 0.25,
        "frequency_factor": 0.8,
        "recency_hours": 10.0,
        "description": "Low-confidence rumor with no supporting operational evidence.",
    },
    {
        "name": "Satirical Post Reposting Aggressive Language",
        "keyword": "violent rhetoric",
        "keyword_weight": 3.7,
        "expected_severity": "low",
        "source_credibility": 0.2,
        "frequency_factor": 0.7,
        "recency_hours": 36.0,
        "description": "Quoted rhetoric with satire indicators and no targeting evidence.",
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
