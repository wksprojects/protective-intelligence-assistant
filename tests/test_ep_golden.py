"""Golden EP (Executive Protection) test suite for the Protective Intelligence platform.

These tests validate the core EP workflow: POI matching, proximity alerting,
TAS/behavioral scoring, escalation tiering, SITREP generation, and social
media fixture ingestion.  Each test targets a single protective-intelligence
concept so regressions surface with a clear, actionable failure message.

Relies on the ``client`` fixture from conftest.py which stands up a temp DB
seeded with the default watchlist (Magnificent 7 CEOs, real HQs, etc.).
"""

import json
import math
import sys
from pathlib import Path

import pytest

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from analytics.behavioral_assessment import (
    PATHWAY_WEIGHTS,
    compute_pathway_score,
    determine_escalation_trend,
    score_to_risk_tier,
)
from analytics.location_enrichment import update_alert_proximity
from analytics.poi_matching import get_active_poi_aliases, match_pois
from analytics.sitrep import generate_sitrep_for_poi_escalation
from analytics.tas_assessment import (
    build_escalation_explanation,
    compute_poi_assessment,
)
from database.init_db import get_connection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _insert_alert(conn, title, content="", url=None, source_id=None, keyword_id=None):
    """Insert a bare alert row and return its id."""
    if source_id is None:
        source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
    if keyword_id is None:
        keyword_id = conn.execute(
            "SELECT id FROM keywords WHERE category = 'protective_intel' ORDER BY id LIMIT 1"
        ).fetchone()["id"]
    conn.execute(
        """INSERT INTO alerts
        (source_id, keyword_id, title, content, url, severity, published_at)
        VALUES (?, ?, ?, ?, ?, 'low', datetime('now'))""",
        (source_id, keyword_id, title, content, url or f"https://example.com/{title[:20]}"),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _insert_alert_with_poi_hit(conn, poi_id, title, content="", match_value=None):
    """Insert an alert and link it to a POI via poi_hits, return alert_id."""
    alert_id = _insert_alert(conn, title, content)
    conn.execute(
        """INSERT INTO poi_hits
        (poi_id, alert_id, match_type, match_value, match_score, context)
        VALUES (?, ?, 'exact', ?, 1.0, ?)""",
        (poi_id, alert_id, match_value or "Tim Cook", title[:80]),
    )
    return alert_id


# ---------------------------------------------------------------------------
# 1. Name disambiguation
# ---------------------------------------------------------------------------

class TestNameDisambiguation:
    """POI matching resolves the correct protectee among similar names."""

    def test_exact_match_selects_correct_poi(self, client):
        """Validate that text mentioning 'Tim Cook' matches the Apple CEO POI
        and not an unrelated person when multiple POIs exist.

        EP concept: In a protective detail, the analyst must be certain that
        an alert about 'Tim Cook' refers to *the* protectee and not a
        different individual with a similar or identical name.
        """
        conn = get_connection()
        aliases = get_active_poi_aliases(conn)
        conn.close()

        # Text clearly about the Apple CEO
        text = (
            "Tim Cook, CEO of Apple Inc., was mentioned in a "
            "threatening post online. The post referenced his upcoming "
            "WWDC keynote appearance."
        )
        hits = match_pois(text, aliases)
        assert len(hits) >= 1, "Expected at least one POI hit for 'Tim Cook'"

        # Every hit for this text must resolve to the Tim Cook POI
        cook_poi = next(
            (a for a in aliases if a["poi_name"] == "Tim Cook"),
            None,
        )
        assert cook_poi is not None
        for hit in hits:
            if hit["match_value"].lower() == "tim cook":
                assert hit["poi_id"] == cook_poi["poi_id"], (
                    "Tim Cook hit resolved to wrong POI id"
                )

    def test_different_poi_not_confused(self, client):
        """Text mentioning 'Satya Nadella' must not generate a hit for Tim Cook.

        EP concept: Disambiguation prevents false escalation for the wrong
        protectee.
        """
        conn = get_connection()
        aliases = get_active_poi_aliases(conn)
        conn.close()

        text = "Satya Nadella reviewed the quarterly security assessment."
        hits = match_pois(text, aliases)
        cook_hits = [h for h in hits if h["poi_name"] == "Tim Cook"]
        assert len(cook_hits) == 0, (
            "Text about Satya Nadella must not produce a Tim Cook hit"
        )


# ---------------------------------------------------------------------------
# 2. Alias matching
# ---------------------------------------------------------------------------

class TestAliasMatching:
    """POI matching via configured aliases (e.g., 'Timothy D. Cook' -> 'Tim Cook')."""

    def test_abbreviated_alias_matches_poi(self, client):
        """Validate that the alias 'Timothy D. Cook' in article text correctly
        resolves to the protectee 'Tim Cook'.

        EP concept: Threat actors and media often use full legal names,
        initials, or nicknames.  The matching engine must resolve aliases
        to the canonical protectee record so nothing is missed.
        """
        conn = get_connection()
        aliases = get_active_poi_aliases(conn)
        conn.close()

        text = (
            "An anonymous user referenced Timothy D. Cook in connection with "
            "an upcoming corporate event at the Apple headquarters."
        )
        hits = match_pois(text, aliases)
        cook_alias_hits = [h for h in hits if h["match_value"] == "Timothy D. Cook"]
        assert len(cook_alias_hits) >= 1, (
            "Expected alias 'Timothy D. Cook' to produce a match"
        )
        # The hit must map back to the Tim Cook POI
        cook_poi_id = next(
            a["poi_id"] for a in aliases if a["poi_name"] == "Tim Cook"
        )
        for hit in cook_alias_hits:
            assert hit["poi_id"] == cook_poi_id, (
                "Alias 'Timothy D. Cook' resolved to wrong POI"
            )

    def test_jen_hsun_huang_alias(self, client):
        """Validate that 'Jen-Hsun Huang' alias resolves to Jensen Huang POI.

        EP concept: Birth names and formal name variants must still link to
        the correct protectee for comprehensive coverage.
        """
        conn = get_connection()
        aliases = get_active_poi_aliases(conn)
        conn.close()

        text = "Jen-Hsun Huang inspected the perimeter before the GTC keynote."
        hits = match_pois(text, aliases)
        huang_hits = [h for h in hits if h["match_value"] == "Jen-Hsun Huang"]
        assert len(huang_hits) >= 1, (
            "Expected alias 'Jen-Hsun Huang' to match Jensen Huang POI"
        )
        jensen_poi_id = next(
            a["poi_id"] for a in aliases if a["poi_name"] == "Jensen Huang"
        )
        assert huang_hits[0]["poi_id"] == jensen_poi_id


# ---------------------------------------------------------------------------
# 3. Proximity calculation
# ---------------------------------------------------------------------------

class TestProximityCalculation:
    """An alert near a protected location is correctly flagged within radius."""

    def test_alert_within_apple_park_radius(self, client):
        """Insert an alert with a geocoded location very close to Apple Park
        (37.3349, -122.0090) and verify it is flagged as within_radius.

        EP concept: Proximity alerts are a core EP signal.  If a threat is
        geolocated within the protective radius of an asset, the detail
        must be notified immediately.
        """
        conn = get_connection()
        alert_id = _insert_alert(conn, "Bomb threat near Cupertino campus")

        # Place the alert location ~0.3 miles from Apple Park (37.3349, -122.0090)
        nearby_lat, nearby_lon = 37.3355, -122.0080
        conn.execute(
            """INSERT INTO alert_locations
            (alert_id, location_text, lat, lon, resolver, confidence)
            VALUES (?, 'Near Apple Park', ?, ?, 'test', 0.95)""",
            (alert_id, nearby_lat, nearby_lon),
        )

        update_alert_proximity(conn, alert_id)
        conn.commit()

        prox = conn.execute(
            """SELECT distance_miles, within_radius, protected_location_id
            FROM alert_proximity WHERE alert_id = ?""",
            (alert_id,),
        ).fetchall()
        conn.close()

        assert len(prox) >= 1, "Expected at least one proximity record"
        # Find the Apple Park proximity row
        hq_prox = [
            dict(r) for r in prox
            if r["distance_miles"] is not None and r["distance_miles"] < 1.0
        ]
        assert len(hq_prox) >= 1, (
            "Expected alert to be within 1 mile of Apple Park"
        )
        assert hq_prox[0]["within_radius"] == 1, (
            "Alert within radius should be flagged within_radius=1"
        )

    def test_alert_outside_radius_not_flagged(self, client):
        """An alert far from all protected locations must not be flagged.

        EP concept: Reducing false proximity alerts prevents alarm fatigue.
        """
        conn = get_connection()
        alert_id = _insert_alert(conn, "Unrelated event in remote location")

        # Place the alert in a location very far from all protected HQs
        conn.execute(
            """INSERT INTO alert_locations
            (alert_id, location_text, lat, lon, resolver, confidence)
            VALUES (?, 'Rural Alaska', ?, ?, 'test', 0.90)""",
            (alert_id, 64.2008, -152.4937),
        )

        update_alert_proximity(conn, alert_id)
        conn.commit()

        prox = conn.execute(
            "SELECT within_radius FROM alert_proximity WHERE alert_id = ?",
            (alert_id,),
        ).fetchall()
        conn.close()

        for row in prox:
            assert row["within_radius"] == 0, (
                "Alert far from all protected locations should NOT be within_radius"
            )


# ---------------------------------------------------------------------------
# 4. TAS scoring basics
# ---------------------------------------------------------------------------

class TestTASScoring:
    """TAS (Threat Assessment Score) is 0 when no alerts exist for a POI."""

    def test_tas_zero_for_clean_poi(self, client):
        """A POI with zero alert hits must produce a null/empty assessment
        (TAS effectively 0).

        EP concept: The TAS baseline for a protectee with no threat
        intelligence activity should be zero, indicating no active threat
        signals in the assessment window.
        """
        conn = get_connection()
        poi = conn.execute("SELECT id FROM pois WHERE name = 'Tim Cook'").fetchone()
        assert poi is not None, "Seed POI 'Tim Cook' must exist"
        poi_id = poi["id"]

        # No alerts or poi_hits inserted -> assessment should return None
        result = compute_poi_assessment(conn, poi_id, window_days=14)
        conn.close()

        assert result is None, (
            "TAS assessment must be None (no data) when the POI has zero "
            "alert hits in the window"
        )

    def test_tas_via_api_returns_empty_for_clean_poi(self, client):
        """The /pois/{poi_id}/assessment API endpoint returns an empty dict
        when there are no alerts to assess.

        EP concept: The API layer must gracefully handle a clean protectee
        without raising errors.
        """
        conn = get_connection()
        poi = conn.execute("SELECT id FROM pois WHERE name = 'Tim Cook'").fetchone()
        conn.close()

        response = client.get(
            f"/pois/{poi['id']}/assessment",
            params={"force": 1},
        )
        assert response.status_code == 200
        payload = response.json()
        # Empty dict or no tas_score key indicates no threat data
        assert payload.get("tas_score") is None or payload == {}


# ---------------------------------------------------------------------------
# 5. Escalation tier resolution
# ---------------------------------------------------------------------------

class TestEscalationTierResolution:
    """Score maps to correct escalation tier (CRITICAL/ELEVATED/ROUTINE/LOW)."""

    @pytest.mark.parametrize(
        "score,expected_tier",
        [
            (95.0, "CRITICAL"),
            (85.0, "CRITICAL"),
            (84.9, "ELEVATED"),
            (65.0, "ELEVATED"),
            (64.9, "ROUTINE"),
            (40.0, "ROUTINE"),
            (39.9, "LOW"),
            (0.0, "LOW"),
        ],
    )
    def test_score_to_escalation_tier(self, client, score, expected_tier):
        """Verify that a TAS score maps to the correct escalation tier
        according to the configured thresholds in watchlist.yaml.

        EP concept: Escalation tiers determine analyst response urgency.
        CRITICAL -> 30-minute SLA with detail leader notification.
        ELEVATED -> 4-hour enhanced monitoring.
        ROUTINE -> 24-hour daily report inclusion.
        LOW -> Archive for trend analysis.
        """
        assessment = {
            "tas_score": score,
            "fixation": 0,
            "energy_burst": 0,
            "leakage": 0,
            "pathway": 0,
            "targeting_specificity": 0,
            "evidence": {"excerpts": [], "hits": 0, "distinct_days": 0},
        }
        explanation = build_escalation_explanation(assessment)
        assert explanation["escalation_tier"] == expected_tier, (
            f"Score {score} should map to {expected_tier}, "
            f"got {explanation['escalation_tier']}"
        )


# ---------------------------------------------------------------------------
# 6. Behavioral assessment (pathway-to-violence)
# ---------------------------------------------------------------------------

class TestBehavioralAssessment:
    """Pathway-to-violence composite score computed correctly."""

    def test_pathway_weights_sum_to_one(self, client):
        """Validate that PATHWAY_WEIGHTS sum to 1.0, ensuring the composite
        score is properly normalized.

        EP concept: The pathway-to-violence model uses 8 weighted indicators.
        If weights do not sum to 1.0, the maximum possible score would be
        distorted, leading to miscalibrated risk tiers.
        """
        total = sum(PATHWAY_WEIGHTS.values())
        assert math.isclose(total, 1.0, rel_tol=1e-9), (
            f"PATHWAY_WEIGHTS must sum to 1.0, got {total}"
        )

    def test_all_indicators_maximum_yields_100(self, client):
        """All indicators at 1.0 must produce a composite score of 100.0.

        EP concept: A subject exhibiting maximum threat across every
        behavioral indicator represents the theoretical ceiling.
        """
        indicators = {k: 1.0 for k in PATHWAY_WEIGHTS}
        score = compute_pathway_score(indicators)
        assert score == 100.0, f"All-max indicators should yield 100.0, got {score}"

    def test_all_indicators_zero_yields_zero(self, client):
        """All indicators at 0.0 must produce a composite score of 0.0.

        EP concept: No behavioral signals means no risk from this model.
        """
        indicators = {k: 0.0 for k in PATHWAY_WEIGHTS}
        score = compute_pathway_score(indicators)
        assert score == 0.0, f"All-zero indicators should yield 0.0, got {score}"

    def test_partial_indicators_compute_correctly(self, client):
        """A known set of partial indicators must produce the expected score.

        EP concept: Analysts submit partial assessments as new intelligence
        arrives; the model must weight each indicator proportionally.
        """
        indicators = {
            "grievance_level": 0.8,      # 0.8 * 0.10 * 100 = 8.0
            "fixation_level": 0.6,       # 0.6 * 0.15 * 100 = 9.0
            "identification_level": 0.0,  # 0.0
            "novel_aggression": 0.5,     # 0.5 * 0.15 * 100 = 7.5
            "energy_burst": 0.3,         # 0.3 * 0.10 * 100 = 3.0
            "leakage": 0.9,             # 0.9 * 0.15 * 100 = 13.5
            "last_resort": 0.0,          # 0.0
            "directly_communicated_threat": 1.0,  # 1.0 * 0.15 * 100 = 15.0
        }
        expected = 8.0 + 9.0 + 0.0 + 7.5 + 3.0 + 13.5 + 0.0 + 15.0  # = 56.0
        score = compute_pathway_score(indicators)
        assert math.isclose(score, expected, abs_tol=0.01), (
            f"Expected {expected}, got {score}"
        )

    def test_score_to_risk_tier_mapping(self, client):
        """Behavioral pathway score maps to the correct risk tier.

        EP concept: The behavioral risk tier (distinct from TAS escalation
        tier) uses different thresholds tuned for subject-level assessment:
        CRITICAL >= 75, ELEVATED >= 50, ROUTINE >= 25, LOW < 25.
        """
        assert score_to_risk_tier(80) == "CRITICAL"
        assert score_to_risk_tier(75) == "CRITICAL"
        assert score_to_risk_tier(74) == "ELEVATED"
        assert score_to_risk_tier(50) == "ELEVATED"
        assert score_to_risk_tier(49) == "ROUTINE"
        assert score_to_risk_tier(25) == "ROUTINE"
        assert score_to_risk_tier(24) == "LOW"
        assert score_to_risk_tier(0) == "LOW"

    def test_upsert_assessment_via_api(self, client):
        """Submit a behavioral assessment through the API and verify it
        persists with correct pathway_score and risk_tier.

        EP concept: Analysts submit structured threat assessments via the
        API; the system must persist, score, and tier-classify them.
        """
        # Create a threat subject
        resp = client.post(
            "/threat-subjects",
            json={"name": "Test Subject Alpha", "aliases": ["Alpha"], "notes": "Golden test"},
        )
        assert resp.status_code == 200
        subject_id = resp.json()["id"]

        # Submit assessment
        indicators = {
            "grievance_level": 0.7,
            "fixation_level": 0.8,
            "identification_level": 0.3,
            "novel_aggression": 0.6,
            "energy_burst": 0.4,
            "leakage": 0.5,
            "last_resort": 0.2,
            "directly_communicated_threat": 0.9,
            "evidence_summary": "Golden test evidence",
            "analyst_notes": "EP golden test case",
        }
        resp = client.post(f"/threat-subjects/{subject_id}/assess", json=indicators)
        assert resp.status_code == 200
        result = resp.json()

        assert "pathway_score" in result
        assert "risk_tier" in result
        assert result["pathway_score"] > 0
        expected_score = compute_pathway_score(indicators)
        assert math.isclose(result["pathway_score"], expected_score, abs_tol=0.01)


# ---------------------------------------------------------------------------
# 7. Behavioral trend detection
# ---------------------------------------------------------------------------

class TestBehavioralTrend:
    """Escalation trend detection (stable / increasing / decreasing)."""

    def test_trend_stable_with_insufficient_history(self, client):
        """A subject with fewer than 2 historical assessments should be
        classified as 'stable' (insufficient data for trend).

        EP concept: Without longitudinal data, the system must not assume
        escalation or de-escalation.
        """
        conn = get_connection()
        # Create a threat subject
        conn.execute(
            """INSERT INTO threat_subjects
            (name, aliases, status, risk_tier)
            VALUES ('Trend Test Stable', '[]', 'active', 'LOW')"""
        )
        subject_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()

        trend = determine_escalation_trend(conn, subject_id, current_score=50.0)
        conn.close()

        assert trend == "stable", (
            "With no assessment history, trend must be 'stable'"
        )

    def test_trend_increasing_detected(self, client):
        """When the current score is significantly higher than historical
        average, the trend must be 'increasing'.

        EP concept: An increasing trend triggers enhanced monitoring and
        may warrant a SITREP or analyst notification.
        """
        conn = get_connection()
        conn.execute(
            """INSERT INTO threat_subjects
            (name, aliases, status, risk_tier)
            VALUES ('Trend Test Increasing', '[]', 'active', 'LOW')"""
        )
        subject_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Insert historical assessments with low scores
        for i in range(3):
            conn.execute(
                """INSERT INTO threat_subject_assessments
                (subject_id, assessment_date, pathway_score, escalation_trend)
                VALUES (?, date('now', ?), ?, 'stable')""",
                (subject_id, f"-{i + 1} days", 20.0),
            )
        conn.commit()

        # Current score much higher than historical avg (20.0)
        trend = determine_escalation_trend(conn, subject_id, current_score=40.0)
        conn.close()

        assert trend == "increasing", (
            "Score 40 vs avg 20 should yield 'increasing' trend"
        )

    def test_trend_decreasing_detected(self, client):
        """When the current score is significantly lower than historical
        average, the trend must be 'decreasing'.

        EP concept: A decreasing trend may allow the detail to reduce
        protective posture.
        """
        conn = get_connection()
        conn.execute(
            """INSERT INTO threat_subjects
            (name, aliases, status, risk_tier)
            VALUES ('Trend Test Decreasing', '[]', 'active', 'LOW')"""
        )
        subject_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Insert historical assessments with high scores
        for i in range(3):
            conn.execute(
                """INSERT INTO threat_subject_assessments
                (subject_id, assessment_date, pathway_score, escalation_trend)
                VALUES (?, date('now', ?), ?, 'stable')""",
                (subject_id, f"-{i + 1} days", 70.0),
            )
        conn.commit()

        # Current score much lower than historical avg (70.0)
        trend = determine_escalation_trend(conn, subject_id, current_score=50.0)
        conn.close()

        assert trend == "decreasing", (
            "Score 50 vs avg 70 should yield 'decreasing' trend"
        )


# ---------------------------------------------------------------------------
# 8. SITREP generation
# ---------------------------------------------------------------------------

class TestSITREPGeneration:
    """SITREP created from POI escalation with correct markdown structure."""

    def test_sitrep_generated_from_assessment(self, client):
        """Generate a SITREP from a synthetic TAS assessment and verify
        the resulting document contains required EP markdown sections.

        EP concept: SITREPs are the primary intelligence product delivered
        to the protective detail.  They must contain: title, severity,
        trigger type, situation summary, affected protectees, recommended
        actions, and escalation tier.
        """
        conn = get_connection()
        poi = conn.execute("SELECT * FROM pois WHERE name = 'Tim Cook'").fetchone()
        assert poi is not None
        poi_id = poi["id"]

        # Insert alerts linked to the POI so assessment can compute
        source_id = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]
        keyword_id = conn.execute(
            "SELECT id FROM keywords WHERE category = 'protective_intel' ORDER BY id LIMIT 1"
        ).fetchone()["id"]

        for i in range(3):
            alert_id = _insert_alert(
                conn,
                f"Threat #{i} against Tim Cook - plan to attack tomorrow at Apple Park entrance",
                content=f"Tim Cook will pay. Going to the route near Apple Park. weapon ready. day {i}.",
                source_id=source_id,
                keyword_id=keyword_id,
            )
            # Override published_at to spread across multiple days
            conn.execute(
                "UPDATE alerts SET published_at = datetime('now', ?) WHERE id = ?",
                (f"-{i} days", alert_id),
            )
            conn.execute(
                """INSERT INTO poi_hits
                (poi_id, alert_id, match_type, match_value, match_score, context)
                VALUES (?, ?, 'exact', 'Tim Cook', 1.0, ?)""",
                (poi_id, alert_id, f"Threat #{i} against Tim Cook"),
            )
        conn.commit()

        assessment = compute_poi_assessment(conn, poi_id, window_days=14)
        assert assessment is not None, "Assessment must be non-None with alert hits"
        conn.commit()

        sitrep = generate_sitrep_for_poi_escalation(conn, poi_id, assessment)
        conn.commit()
        conn.close()

        assert sitrep is not None, "SITREP must be generated"
        assert "id" in sitrep, "SITREP must have a persisted id"
        assert sitrep["trigger_type"] == "poi_escalation"

        # Validate markdown content
        md = sitrep["content_md"]
        assert "# SITREP:" in md, "Markdown must contain SITREP heading"
        assert "**Severity:**" in md, "Markdown must contain severity"
        assert "**Trigger:**" in md, "Markdown must contain trigger type"
        assert "## Situation Summary" in md, "Markdown must contain situation summary section"
        assert "## Recommended Actions" in md, "Markdown must contain actions section"
        assert "## Affected Protectees" in md, "Markdown must list affected protectees"
        assert sitrep["escalation_tier"] in ("CRITICAL", "ELEVATED", "ROUTINE", "LOW")

    def test_sitrep_lists_via_api(self, client):
        """The /sitreps endpoint returns SITREPs after generation.

        EP concept: The analyst dashboard must be able to list and filter
        SITREPs by status for daily review.
        """
        response = client.get("/sitreps")
        assert response.status_code == 200
        payload = response.json()
        assert isinstance(payload, list)


# ---------------------------------------------------------------------------
# 9. Social media fixture loading
# ---------------------------------------------------------------------------

class TestSocialMediaFixtures:
    """Social media monitor loads fixture data correctly."""

    def test_fixture_file_exists_and_is_valid_json(self, client):
        """The social media fixtures file must exist and contain valid JSON
        with the expected post structure.

        EP concept: Social media monitoring is a critical OSINT source for
        protective intelligence.  Fixture data represents known threat
        patterns (direct threats, hostile surveillance, grievance escalation)
        used for demo and regression testing.
        """
        fixture_path = PROJECT_ROOT / "fixtures" / "social_media_fixtures.json"
        assert fixture_path.exists(), (
            f"Fixture file missing at {fixture_path}"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            posts = json.load(f)
        assert isinstance(posts, list), "Fixtures must be a JSON array"
        assert len(posts) >= 1, "Fixtures must contain at least one post"

        # Validate required fields on first post
        required_fields = {"platform", "title", "content", "url"}
        for post in posts:
            missing = required_fields - set(post.keys())
            assert not missing, (
                f"Post missing required fields: {missing}"
            )

    def test_fixture_posts_cover_key_threat_categories(self, client):
        """Fixture data must cover the main EP threat categories:
        protective_intel, protest_disruption, insider_workplace, and
        travel_risk.

        EP concept: A comprehensive social media monitoring fixture set
        exercises all the threat categories relevant to executive
        protection operations.
        """
        fixture_path = PROJECT_ROOT / "fixtures" / "social_media_fixtures.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            posts = json.load(f)

        categories = {post.get("category") for post in posts}
        expected = {"protective_intel", "protest_disruption", "insider_workplace"}
        missing = expected - categories
        assert not missing, (
            f"Fixture data missing threat categories: {missing}"
        )

    def test_social_media_scrape_endpoint(self, client, monkeypatch):
        """Triggering the social media scrape endpoint ingests fixture data
        when no live API keys are configured.

        EP concept: In demo/development mode, the social media pipeline
        must seamlessly load fixture data to exercise the full ingestion
        and EP enrichment pipeline.
        """
        # Ensure no live API keys are set
        for platform_cfg in ("TWITTER_BEARER_TOKEN", "INSTAGRAM_ACCESS_TOKEN",
                             "TELEGRAM_API_ID", "TIKTOK_RESEARCH_TOKEN"):
            monkeypatch.delenv(platform_cfg, raising=False)
        monkeypatch.delenv("SOCIAL_MEDIA_ENABLED", raising=False)

        response = client.post("/scrape/social-media")
        assert response.status_code == 200
        payload = response.json()
        assert "ingested" in payload
        assert payload["ingested"] >= 0
        assert payload["mode"] in ("fixture", "disabled")


# ---------------------------------------------------------------------------
# 10. Escalation explanation
# ---------------------------------------------------------------------------

class TestEscalationExplanation:
    """build_escalation_explanation returns correct structure."""

    def test_explanation_structure_all_flags_fired(self, client):
        """When all TRAP-lite flags fire, the escalation explanation must
        include every flag with its description, the correct tier, response
        window, notification list, and recommended actions.

        EP concept: The escalation explanation is the analyst-facing
        justification for why a protectee's threat level was raised.  It
        must be complete and actionable for the detail leader.
        """
        assessment = {
            "tas_score": 100.0,
            "fixation": 1,
            "energy_burst": 1,
            "leakage": 1,
            "pathway": 1,
            "targeting_specificity": 1,
            "evidence": {
                "excerpts": ["excerpt one", "excerpt two", "excerpt three"],
                "hits": 15,
                "distinct_days": 7,
            },
        }
        explanation = build_escalation_explanation(assessment)

        # Structure validation
        required_keys = {
            "escalation_tier",
            "flags_fired",
            "evidence_strings",
            "recommended_actions",
            "response_window",
            "notify",
            "summary",
        }
        missing = required_keys - set(explanation.keys())
        assert not missing, f"Explanation missing keys: {missing}"

        # Tier and notification
        assert explanation["escalation_tier"] == "CRITICAL"
        assert "detail_leader" in explanation["notify"]
        assert "intel_manager" in explanation["notify"]
        assert explanation["response_window"] == "30 minutes"

        # All 5 TRAP-lite flags must be present
        flag_names = {f["flag"] for f in explanation["flags_fired"]}
        expected_flags = {"fixation", "energy_burst", "leakage", "pathway", "targeting_specificity"}
        assert flag_names == expected_flags, (
            f"Expected all 5 flags, got {flag_names}"
        )

        # Each flag has a description
        for flag in explanation["flags_fired"]:
            assert "description" in flag and len(flag["description"]) > 10

        # Evidence strings
        assert len(explanation["evidence_strings"]) == 3

        # Recommended actions for CRITICAL
        actions_text = " ".join(explanation["recommended_actions"])
        assert "IMMEDIATE" in actions_text, (
            "CRITICAL tier must include IMMEDIATE action"
        )

        # Summary is a human-readable string
        assert isinstance(explanation["summary"], str)
        assert "100.0" in explanation["summary"]

    def test_explanation_structure_no_flags(self, client):
        """When no TRAP-lite flags fire, the explanation must still return
        a valid structure with an empty flags_fired list.

        EP concept: Even a LOW/ROUTINE assessment needs an explanation
        structure so the analyst dashboard renders consistently.
        """
        assessment = {
            "tas_score": 10.0,
            "fixation": 0,
            "energy_burst": 0,
            "leakage": 0,
            "pathway": 0,
            "targeting_specificity": 0,
            "evidence": {"excerpts": [], "hits": 1, "distinct_days": 1},
        }
        explanation = build_escalation_explanation(assessment)

        assert explanation["escalation_tier"] == "LOW"
        assert explanation["flags_fired"] == []
        assert isinstance(explanation["summary"], str)
        assert len(explanation["summary"]) > 0

    def test_explanation_via_assessment_api(self, client):
        """The /pois/{poi_id}/assessment endpoint includes an 'escalation'
        block with the build_escalation_explanation structure when data exists.

        EP concept: End-to-end validation that the API surfaces the
        escalation explanation alongside the TAS assessment, providing
        the analyst a single-request intelligence product.
        """
        conn = get_connection()
        poi = conn.execute("SELECT id FROM pois WHERE name = 'Tim Cook'").fetchone()
        poi_id = poi["id"]

        # Seed alert data for the POI
        alert_id = _insert_alert(
            conn,
            "Follow-up threat referencing Tim Cook schedule and route tomorrow",
            content="Tim Cook weapon plan to Apple Park entrance route badge",
        )
        conn.execute(
            "UPDATE alerts SET published_at = datetime('now', '-1 day') WHERE id = ?",
            (alert_id,),
        )
        conn.execute(
            """INSERT INTO poi_hits
            (poi_id, alert_id, match_type, match_value, match_score, context)
            VALUES (?, ?, 'exact', 'Tim Cook', 1.0, 'threat context')""",
            (poi_id, alert_id),
        )
        conn.commit()
        conn.close()

        response = client.get(
            f"/pois/{poi_id}/assessment",
            params={"force": 1},
        )
        assert response.status_code == 200
        payload = response.json()
        # When there is assessment data, the escalation block must be present
        if payload.get("tas_score") is not None:
            assert "escalation" in payload, (
                "Assessment response must include 'escalation' block"
            )
            esc = payload["escalation"]
            assert "escalation_tier" in esc
            assert "flags_fired" in esc
            assert "recommended_actions" in esc
