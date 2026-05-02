"""Unit tests for analytics.insider_risk — insider-risk scoring engine."""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from analytics.insider_risk import (
    SIGNAL_WEIGHTS,
    _as_bool,
    _clamp,
    _parse_json,
    _safe_float,
    _score_to_tier,
    build_subject_assessments,
    evaluate_scored_events,
    score_insider_event,
)

# ===========================================================================
# _safe_float
# ===========================================================================


class TestSafeFloat:
    def test_valid_int(self):
        assert _safe_float(5) == 5.0

    def test_valid_float(self):
        assert _safe_float(3.14) == 3.14

    def test_valid_string(self):
        assert _safe_float("2.5") == 2.5

    def test_none_returns_default(self):
        assert _safe_float(None) == 0.0

    def test_none_with_custom_default(self):
        assert _safe_float(None, default=1.0) == 1.0

    def test_non_numeric_string(self):
        assert _safe_float("abc") == 0.0

    def test_empty_string(self):
        assert _safe_float("") == 0.0

    def test_bool_true(self):
        assert _safe_float(True) == 1.0

    def test_bool_false(self):
        assert _safe_float(False) == 0.0


# ===========================================================================
# _clamp
# ===========================================================================


class TestClamp:
    def test_within_bounds(self):
        assert _clamp(0.5) == 0.5

    def test_below_lower(self):
        assert _clamp(-1.0) == 0.0

    def test_above_upper(self):
        assert _clamp(2.0) == 1.0

    def test_at_boundaries(self):
        assert _clamp(0.0) == 0.0
        assert _clamp(1.0) == 1.0

    def test_custom_bounds(self):
        assert _clamp(5.0, lower=0.0, upper=10.0) == 5.0
        assert _clamp(15.0, lower=0.0, upper=10.0) == 10.0


# ===========================================================================
# _as_bool
# ===========================================================================


class TestAsBool:
    def test_true_values(self):
        assert _as_bool(True) is True
        assert _as_bool("1") is True
        assert _as_bool("true") is True
        assert _as_bool("yes") is True
        assert _as_bool("on") is True
        assert _as_bool("True") is True

    def test_false_values(self):
        assert _as_bool(False) is False
        assert _as_bool("0") is False
        assert _as_bool("false") is False
        assert _as_bool("no") is False
        assert _as_bool(None) is False
        assert _as_bool("") is False


# ===========================================================================
# _parse_json (called _parse_json_or_default in task description)
# ===========================================================================


class TestParseJson:
    def test_none_returns_fallback(self):
        assert _parse_json(None, []) == []

    def test_list_passthrough(self):
        data = [1, 2, 3]
        assert _parse_json(data, []) is data

    def test_dict_passthrough(self):
        data = {"a": 1}
        assert _parse_json(data, {}) is data

    def test_valid_json_string(self):
        assert _parse_json('{"key": "val"}', {}) == {"key": "val"}

    def test_invalid_json_returns_fallback(self):
        assert _parse_json("not json", "default") == "default"

    def test_empty_string_returns_fallback(self):
        assert _parse_json("", []) == []


# ===========================================================================
# _score_to_tier
# ===========================================================================


class TestScoreToTier:
    def test_critical(self):
        assert _score_to_tier(85.0) == "CRITICAL"
        assert _score_to_tier(100.0) == "CRITICAL"

    def test_high(self):
        assert _score_to_tier(70.0) == "HIGH"
        assert _score_to_tier(84.99) == "HIGH"

    def test_elevated(self):
        assert _score_to_tier(50.0) == "ELEVATED"
        assert _score_to_tier(69.99) == "ELEVATED"

    def test_low(self):
        assert _score_to_tier(0.0) == "LOW"
        assert _score_to_tier(49.99) == "LOW"

    def test_boundary_at_85(self):
        assert _score_to_tier(84.999) == "HIGH"
        assert _score_to_tier(85.0) == "CRITICAL"

    def test_boundary_at_70(self):
        assert _score_to_tier(69.999) == "ELEVATED"
        assert _score_to_tier(70.0) == "HIGH"

    def test_boundary_at_50(self):
        assert _score_to_tier(49.999) == "LOW"
        assert _score_to_tier(50.0) == "ELEVATED"


# ===========================================================================
# Factor signal functions (via score_insider_event)
# ===========================================================================


def _score_event_signals(event_overrides):
    """Helper: score an event and return just the signals dict."""
    return score_insider_event(event_overrides)["signals"]


class TestAccessPatternFactor:
    def test_all_zeros(self):
        signals = _score_event_signals({})
        assert signals["access_pattern_deviation"] == 0.0

    def test_high_off_hours(self):
        event = {
            "access": {
                "off_hours_ratio": 1.0,
                "frequency_zscore": 0,
                "sensitive_resource_touches": 0,
                "new_sensitive_repos": 0,
            }
        }
        signals = _score_event_signals(event)
        assert signals["access_pattern_deviation"] == pytest.approx(0.35, abs=0.01)

    def test_all_maxed(self):
        event = {
            "access": {
                "off_hours_ratio": 1.0,
                "frequency_zscore": 4.0,
                "sensitive_resource_touches": 20,
                "new_sensitive_repos": 5,
            }
        }
        signals = _score_event_signals(event)
        assert signals["access_pattern_deviation"] == pytest.approx(1.0, abs=0.01)


class TestDataVolumeFactor:
    def test_zero_movement(self):
        signals = _score_event_signals({})
        assert signals["data_volume_anomaly"] == 0.0

    def test_large_download(self):
        event = {
            "data_movement": {
                "download_gb": 10.0,
                "baseline_gb": 1.0,
                "usb_write_events": 0,
                "cloud_upload_mb": 0,
            }
        }
        signals = _score_event_signals(event)
        assert signals["data_volume_anomaly"] > 0.3

    def test_usb_and_cloud(self):
        event = {
            "data_movement": {
                "download_gb": 0,
                "baseline_gb": 1.0,
                "usb_write_events": 8,
                "cloud_upload_mb": 20000,
            }
        }
        signals = _score_event_signals(event)
        assert signals["data_volume_anomaly"] == pytest.approx(0.5, abs=0.01)


class TestPhysicalLogicalFactor:
    def test_clean_profile(self):
        signals = _score_event_signals({})
        # badge_present is falsy, so badge_alignment_penalty = 1.0 -> 0.15 * 1.0
        assert signals["physical_logical_mismatch"] == pytest.approx(0.15, abs=0.01)

    def test_impossible_travel(self):
        event = {
            "physical_logical": {
                "impossible_travel_events": 2,
                "badge_present": True,
                "login_without_badge_count": 0,
                "after_hours_badge_swipes": 1,
            }
        }
        signals = _score_event_signals(event)
        assert signals["physical_logical_mismatch"] >= 0.4


class TestAccessEscalationFactor:
    def test_no_escalation(self):
        signals = _score_event_signals({})
        assert signals["access_escalation"] == 0.0

    def test_privilege_changes(self):
        event = {"access_escalation": {"privilege_change_events": 3, "failed_admin_attempts": 0}}
        signals = _score_event_signals(event)
        assert signals["access_escalation"] == pytest.approx(0.6, abs=0.01)

    def test_failed_admin(self):
        event = {"access_escalation": {"privilege_change_events": 0, "failed_admin_attempts": 10}}
        signals = _score_event_signals(event)
        assert signals["access_escalation"] == pytest.approx(0.4, abs=0.01)


class TestCommunicationFactor:
    def test_zero(self):
        signals = _score_event_signals({})
        assert signals["communication_metadata_anomaly"] == 0.0

    def test_after_hours_ratio(self):
        event = {
            "communications": {
                "after_hours_ratio": 1.0,
                "new_external_contacts": 0,
                "external_contact_baseline": 1,
                "new_encrypted_channels": 0,
            }
        }
        signals = _score_event_signals(event)
        assert signals["communication_metadata_anomaly"] == pytest.approx(0.4, abs=0.01)


class TestHRContextFactor:
    def test_no_flags(self):
        signals = _score_event_signals({})
        assert signals["hr_context_risk"] == 0.0

    def test_pip_only(self):
        event = {
            "hr_flags": {"pip": True, "resignation_pending": False, "termination_pending": False}
        }
        signals = _score_event_signals(event)
        assert signals["hr_context_risk"] == pytest.approx(0.25, abs=0.01)

    def test_termination_only(self):
        event = {
            "hr_flags": {"pip": False, "resignation_pending": False, "termination_pending": True}
        }
        signals = _score_event_signals(event)
        assert signals["hr_context_risk"] == pytest.approx(0.40, abs=0.01)

    def test_all_flags(self):
        event = {
            "hr_flags": {"pip": True, "resignation_pending": True, "termination_pending": True}
        }
        signals = _score_event_signals(event)
        assert signals["hr_context_risk"] == pytest.approx(1.0, abs=0.01)


class TestTemporalFactor:
    def test_zero(self):
        signals = _score_event_signals({})
        assert signals["temporal_anomaly"] == 0.0

    def test_weekend_sessions(self):
        event = {"temporal": {"weekend_sessions": 4, "overnight_sessions": 0}}
        signals = _score_event_signals(event)
        assert signals["temporal_anomaly"] == pytest.approx(0.45, abs=0.01)

    def test_overnight_sessions(self):
        event = {"temporal": {"weekend_sessions": 0, "overnight_sessions": 6}}
        signals = _score_event_signals(event)
        assert signals["temporal_anomaly"] == pytest.approx(0.55, abs=0.01)


# ===========================================================================
# score_insider_event (integration)
# ===========================================================================


class TestScoreInsiderEvent:
    def test_empty_event_returns_low(self):
        result = score_insider_event({})
        assert result["risk_tier"] == "LOW"
        assert result["event_score"] >= 0.0
        assert "signals" in result
        assert "reason_codes" in result

    def test_high_risk_profile(self):
        event = {
            "scenario_id": "sc-001",
            "subject_id": "emp-42",
            "subject_name": "Jane Doe",
            "access": {
                "off_hours_ratio": 0.9,
                "frequency_zscore": 3.5,
                "sensitive_resource_touches": 15,
                "new_sensitive_repos": 4,
            },
            "data_movement": {
                "download_gb": 8.0,
                "baseline_gb": 1.0,
                "usb_write_events": 6,
                "cloud_upload_mb": 15000,
            },
            "access_escalation": {"privilege_change_events": 3, "failed_admin_attempts": 8},
            "hr_flags": {"pip": True, "resignation_pending": True, "termination_pending": True},
            "temporal": {"weekend_sessions": 4, "overnight_sessions": 5},
            "communications": {
                "after_hours_ratio": 0.8,
                "new_external_contacts": 10,
                "external_contact_baseline": 1,
                "new_encrypted_channels": 4,
            },
            "physical_logical": {
                "badge_present": False,
                "login_without_badge_count": 4,
                "impossible_travel_events": 2,
                "after_hours_badge_swipes": 0,
            },
        }
        result = score_insider_event(event)
        assert result["risk_tier"] in ("HIGH", "CRITICAL")
        assert result["event_score"] >= 70.0
        assert result["subject_id"] == "emp-42"
        assert len(result["reason_codes"]) > 0

    def test_all_zeros_gives_minimal_score(self):
        event = {
            "access": {
                "off_hours_ratio": 0,
                "frequency_zscore": 0,
                "sensitive_resource_touches": 0,
                "new_sensitive_repos": 0,
            },
            "data_movement": {
                "download_gb": 0,
                "baseline_gb": 1,
                "usb_write_events": 0,
                "cloud_upload_mb": 0,
            },
            "access_escalation": {"privilege_change_events": 0, "failed_admin_attempts": 0},
            "hr_flags": {"pip": False, "resignation_pending": False, "termination_pending": False},
            "temporal": {"weekend_sessions": 0, "overnight_sessions": 0},
            "communications": {
                "after_hours_ratio": 0,
                "new_external_contacts": 0,
                "external_contact_baseline": 1,
                "new_encrypted_channels": 0,
            },
            "physical_logical": {
                "badge_present": True,
                "login_without_badge_count": 0,
                "impossible_travel_events": 0,
                "after_hours_badge_swipes": 1,
            },
        }
        result = score_insider_event(event)
        assert result["event_score"] < 30.0
        assert result["risk_tier"] == "LOW"

    def test_reason_codes_max_10(self):
        """Reason codes list should never exceed _MAX_REASON_CODES (10)."""
        event = {
            "access": {
                "off_hours_ratio": 1.0,
                "frequency_zscore": 4.0,
                "sensitive_resource_touches": 20,
                "new_sensitive_repos": 5,
            },
            "data_movement": {
                "download_gb": 50,
                "baseline_gb": 1,
                "usb_write_events": 8,
                "cloud_upload_mb": 20000,
            },
            "access_escalation": {"privilege_change_events": 3, "failed_admin_attempts": 10},
            "hr_flags": {"pip": True, "resignation_pending": True, "termination_pending": True},
            "temporal": {"weekend_sessions": 4, "overnight_sessions": 6},
            "communications": {
                "after_hours_ratio": 1.0,
                "new_external_contacts": 20,
                "external_contact_baseline": 1,
                "new_encrypted_channels": 4,
            },
            "physical_logical": {
                "badge_present": False,
                "login_without_badge_count": 4,
                "impossible_travel_events": 2,
                "after_hours_badge_swipes": 0,
            },
            "taxonomy": {
                "pre_attack_reconnaissance": True,
                "data_staging": True,
                "exfiltration_indicators": True,
                "access_escalation": True,
                "temporal_anomalies": True,
            },
        }
        result = score_insider_event(event)
        assert len(result["reason_codes"]) <= 10

    def test_missing_fields_no_crash(self):
        """Passing partial/missing sub-dicts should not raise."""
        result = score_insider_event({"subject_id": "emp-99"})
        assert result["subject_id"] == "emp-99"
        assert isinstance(result["signals"], dict)

    def test_signal_weights_sum_to_one(self):
        total = sum(SIGNAL_WEIGHTS.values())
        assert total == pytest.approx(1.0, abs=0.001)

    def test_event_score_capped_at_100(self):
        event = {
            "access": {
                "off_hours_ratio": 1.0,
                "frequency_zscore": 4.0,
                "sensitive_resource_touches": 20,
                "new_sensitive_repos": 5,
            },
            "data_movement": {
                "download_gb": 100,
                "baseline_gb": 0.25,
                "usb_write_events": 100,
                "cloud_upload_mb": 100000,
            },
            "access_escalation": {"privilege_change_events": 100, "failed_admin_attempts": 100},
            "hr_flags": {"pip": True, "resignation_pending": True, "termination_pending": True},
            "temporal": {"weekend_sessions": 100, "overnight_sessions": 100},
            "communications": {
                "after_hours_ratio": 1.0,
                "new_external_contacts": 100,
                "external_contact_baseline": 1,
                "new_encrypted_channels": 100,
            },
            "physical_logical": {
                "badge_present": False,
                "login_without_badge_count": 100,
                "impossible_travel_events": 100,
                "after_hours_badge_swipes": 0,
            },
        }
        result = score_insider_event(event)
        assert result["event_score"] <= 100.0


# ===========================================================================
# build_subject_assessments
# ===========================================================================


class TestBuildSubjectAssessments:
    def _make_scored_event(
        self, subject_id, event_score, event_ts="2025-06-15T10:00:00Z", **overrides
    ):
        base = {
            "subject_id": subject_id,
            "subject_name": f"Name-{subject_id}",
            "subject_handle": None,
            "event_score": event_score,
            "event_ts": event_ts,
            "risk_tier": _score_to_tier(event_score),
            "signals": {k: 0.0 for k in SIGNAL_WEIGHTS},
            "reason_codes": [],
            "taxonomy_hits": [],
        }
        base.update(overrides)
        return base

    def test_single_event(self):
        events = [self._make_scored_event("emp-1", 60.0)]
        assessments = build_subject_assessments(events)
        assert len(assessments) == 1
        assert assessments[0]["subject_id"] == "emp-1"
        assert assessments[0]["event_count"] == 1

    def test_multiple_subjects_sorted_by_score(self):
        events = [
            self._make_scored_event("emp-low", 20.0),
            self._make_scored_event("emp-high", 90.0),
        ]
        assessments = build_subject_assessments(events)
        assert assessments[0]["subject_id"] == "emp-high"
        assert assessments[1]["subject_id"] == "emp-low"

    def test_aggregates_multiple_events(self):
        events = [
            self._make_scored_event("emp-1", 40.0, event_ts="2025-06-14T10:00:00Z"),
            self._make_scored_event("emp-1", 60.0, event_ts="2025-06-15T10:00:00Z"),
        ]
        assessments = build_subject_assessments(events)
        assert len(assessments) == 1
        assert assessments[0]["event_count"] == 2

    def test_empty_input(self):
        assert build_subject_assessments([]) == []

    def test_missing_subject_id_skipped(self):
        events = [self._make_scored_event("", 50.0)]
        assessments = build_subject_assessments(events)
        assert len(assessments) == 0


# ===========================================================================
# evaluate_scored_events
# ===========================================================================


class TestEvaluateScoredEvents:
    def test_all_true_positives(self):
        events = [
            {
                "event_score": 80.0,
                "expected_label": "true_positive",
                "risk_tier": "HIGH",
                "reason_codes": [],
            },
            {
                "event_score": 90.0,
                "expected_label": "positive",
                "risk_tier": "CRITICAL",
                "reason_codes": [],
            },
        ]
        result = evaluate_scored_events(events, threshold=65.0)
        assert result["counts"]["tp"] == 2
        assert result["counts"]["fp"] == 0
        assert result["metrics"]["precision"] == 1.0
        assert result["metrics"]["recall"] == 1.0

    def test_all_true_negatives(self):
        events = [
            {
                "event_score": 10.0,
                "expected_label": "benign",
                "risk_tier": "LOW",
                "reason_codes": [],
            },
        ]
        result = evaluate_scored_events(events, threshold=65.0)
        assert result["counts"]["tn"] == 1
        assert result["counts"]["fp"] == 0

    def test_false_positive(self):
        events = [
            {
                "event_score": 80.0,
                "expected_label": "benign",
                "risk_tier": "HIGH",
                "reason_codes": [],
            },
        ]
        result = evaluate_scored_events(events, threshold=65.0)
        assert result["counts"]["fp"] == 1

    def test_false_negative(self):
        events = [
            {
                "event_score": 30.0,
                "expected_label": "malicious",
                "risk_tier": "LOW",
                "reason_codes": [],
            },
        ]
        result = evaluate_scored_events(events, threshold=65.0)
        assert result["counts"]["fn"] == 1

    def test_empty_events(self):
        result = evaluate_scored_events([], threshold=65.0)
        assert result["counts"]["tp"] == 0
        assert result["metrics"]["f1"] == 0.0

    def test_threshold_is_clamped(self):
        result = evaluate_scored_events([], threshold=200.0)
        assert result["threshold"] == 100.0
