"""Unit tests for analytics/supply_chain_risk.py.

Covers vendor risk scoring, individual risk factors, tier classification,
reason code generation, helper functions, edge cases, and database upsert.
"""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from analytics.supply_chain_risk import (
    COMPLIANCE_RISK,
    COUNTRY_RISK,
    DATA_SENSITIVITY_RISK,
    PRIVILEGE_RISK,
    VENDOR_WEIGHTS,
    _as_bool,
    _build_reason_codes,
    _clamp,
    _parse_json,
    _safe_float,
    _score_to_tier,
    score_vendor_profile,
    upsert_supply_chain_assessments,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(**overrides):
    """Return a minimal vendor profile dict with sensible defaults."""
    base = {
        "profile_id": "V-001",
        "vendor_name": "Acme Corp",
        "country": "US",
        "vendor_domain": "acme.com",
        "privilege_scope": "moderate",
        "data_sensitivity": "moderate",
        "compliance_posture": "adequate",
        "critical_dependency_percent": 20,
        "single_point_of_failure": False,
        "recent_incidents": 0,
    }
    base.update(overrides)
    return base


def _supply_chain_table(conn):
    """Create the supply_chain_risk_assessments table in the given connection."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS supply_chain_risk_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id TEXT NOT NULL UNIQUE,
            vendor_name TEXT NOT NULL,
            country TEXT,
            vendor_domain TEXT,
            vendor_risk_score REAL NOT NULL,
            risk_tier TEXT NOT NULL,
            reason_codes_json TEXT,
            factor_breakdown_json TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.commit()


# ---------------------------------------------------------------------------
# _safe_float
# ---------------------------------------------------------------------------


class TestSafeFloat:
    def test_normal_int(self):
        assert _safe_float(42) == 42.0

    def test_normal_float(self):
        assert _safe_float(3.14) == 3.14

    def test_string_number(self):
        assert _safe_float("7.5") == 7.5

    def test_none_returns_default(self):
        assert _safe_float(None) == 0.0

    def test_none_custom_default(self):
        assert _safe_float(None, default=5.0) == 5.0

    def test_garbage_string(self):
        assert _safe_float("abc", default=1.0) == 1.0

    def test_empty_string(self):
        assert _safe_float("", default=0.0) == 0.0

    def test_bool_true(self):
        # float(True) == 1.0 in Python
        assert _safe_float(True) == 1.0

    def test_bool_false(self):
        assert _safe_float(False) == 0.0


# ---------------------------------------------------------------------------
# _clamp
# ---------------------------------------------------------------------------


class TestClamp:
    def test_within_bounds(self):
        assert _clamp(0.5) == 0.5

    def test_below_lower(self):
        assert _clamp(-0.5) == 0.0

    def test_above_upper(self):
        assert _clamp(1.5) == 1.0

    def test_exact_lower(self):
        assert _clamp(0.0) == 0.0

    def test_exact_upper(self):
        assert _clamp(1.0) == 1.0


# ---------------------------------------------------------------------------
# _as_bool
# ---------------------------------------------------------------------------


class TestAsBool:
    @pytest.mark.parametrize("val", [True, "true", "True", "1", "yes", "on"])
    def test_truthy(self, val):
        assert _as_bool(val) is True

    @pytest.mark.parametrize("val", [False, "false", "0", "no", "", None, "off"])
    def test_falsy(self, val):
        assert _as_bool(val) is False


# ---------------------------------------------------------------------------
# _score_to_tier
# ---------------------------------------------------------------------------


class TestScoreToTier:
    def test_high(self):
        assert _score_to_tier(80.0) == "HIGH"
        assert _score_to_tier(99.9) == "HIGH"

    def test_elevated(self):
        assert _score_to_tier(60.0) == "ELEVATED"
        assert _score_to_tier(79.9) == "ELEVATED"

    def test_guarded(self):
        assert _score_to_tier(40.0) == "GUARDED"
        assert _score_to_tier(59.9) == "GUARDED"

    def test_low(self):
        assert _score_to_tier(0.0) == "LOW"
        assert _score_to_tier(39.9) == "LOW"


# ---------------------------------------------------------------------------
# _parse_json
# ---------------------------------------------------------------------------


class TestParseJson:
    def test_valid_json_string(self):
        assert _parse_json('["a", "b"]', []) == ["a", "b"]

    def test_dict_json_string(self):
        assert _parse_json('{"k": 1}', {}) == {"k": 1}

    def test_none_returns_fallback(self):
        assert _parse_json(None, []) == []

    def test_already_list(self):
        data = [1, 2, 3]
        assert _parse_json(data, []) is data

    def test_already_dict(self):
        data = {"a": 1}
        assert _parse_json(data, {}) is data

    def test_invalid_json_returns_fallback(self):
        assert _parse_json("{bad", "default") == "default"

    def test_integer_returns_fallback(self):
        assert _parse_json(999, "fb") == "fb"


# ---------------------------------------------------------------------------
# _build_reason_codes
# ---------------------------------------------------------------------------


class TestBuildReasonCodes:
    def _zero_factors(self, **overrides):
        f = {
            "geographic_risk": 0.0,
            "concentration_risk": 0.0,
            "privilege_scope_risk": 0.0,
            "data_exposure_risk": 0.0,
            "compliance_posture_risk": 0.0,
        }
        f.update(overrides)
        return f

    def test_all_low_gives_baseline(self):
        codes = _build_reason_codes(self._zero_factors(), incidents=0)
        assert codes == ["baseline_monitoring"]

    def test_geographic_high(self):
        codes = _build_reason_codes(self._zero_factors(geographic_risk=0.65), incidents=0)
        assert "geographic_exposure_high" in codes

    def test_concentration_high(self):
        codes = _build_reason_codes(self._zero_factors(concentration_risk=0.60), incidents=0)
        assert "single_point_of_failure" in codes

    def test_privilege_scope_broad(self):
        codes = _build_reason_codes(self._zero_factors(privilege_scope_risk=0.75), incidents=0)
        assert "privilege_scope_broad" in codes

    def test_data_exposure_high(self):
        codes = _build_reason_codes(self._zero_factors(data_exposure_risk=0.70), incidents=0)
        assert "sensitive_data_exposure" in codes

    def test_compliance_gap(self):
        codes = _build_reason_codes(self._zero_factors(compliance_posture_risk=0.65), incidents=0)
        assert "compliance_posture_gap" in codes

    def test_recent_incidents(self):
        codes = _build_reason_codes(self._zero_factors(), incidents=2)
        assert "recent_incident_history" in codes
        assert "baseline_monitoring" not in codes

    def test_multiple_reason_codes(self):
        factors = self._zero_factors(geographic_risk=0.80, data_exposure_risk=0.90)
        codes = _build_reason_codes(factors, incidents=3)
        assert "geographic_exposure_high" in codes
        assert "sensitive_data_exposure" in codes
        assert "recent_incident_history" in codes
        assert "baseline_monitoring" not in codes


# ---------------------------------------------------------------------------
# Country risk lookup
# ---------------------------------------------------------------------------


class TestCountryRisk:
    def test_known_countries(self):
        assert COUNTRY_RISK["US"] == 0.10
        assert COUNTRY_RISK["KP"] == 0.95

    def test_default_for_unknown(self):
        # score_vendor_profile uses .get(country, 0.40)
        result = score_vendor_profile(_make_profile(country="ZZ"))
        assert result["factors"]["geographic_risk"] == 0.40


# ---------------------------------------------------------------------------
# Individual risk factor scoring
# ---------------------------------------------------------------------------


class TestGeographicExposure:
    def test_low_risk_country(self):
        result = score_vendor_profile(_make_profile(country="US"))
        assert result["factors"]["geographic_risk"] == COUNTRY_RISK["US"]

    def test_high_risk_country(self):
        result = score_vendor_profile(_make_profile(country="RU"))
        assert result["factors"]["geographic_risk"] == COUNTRY_RISK["RU"]

    def test_case_insensitive(self):
        result = score_vendor_profile(_make_profile(country="us"))
        assert result["factors"]["geographic_risk"] == COUNTRY_RISK["US"]


class TestConcentrationRisk:
    def test_no_single_point_low_dependency(self):
        result = score_vendor_profile(
            _make_profile(
                single_point_of_failure=False,
                critical_dependency_percent=0,
            )
        )
        # 0.25 + 0.35 * 0.0 = 0.25
        assert result["factors"]["concentration_risk"] == 0.25

    def test_single_point_full_dependency(self):
        result = score_vendor_profile(
            _make_profile(
                single_point_of_failure=True,
                critical_dependency_percent=100,
            )
        )
        # 0.65 + 0.35 * 1.0 = 1.0
        assert result["factors"]["concentration_risk"] == 1.0

    def test_no_single_point_full_dependency(self):
        result = score_vendor_profile(
            _make_profile(
                single_point_of_failure=False,
                critical_dependency_percent=100,
            )
        )
        # 0.25 + 0.35 * 1.0 = 0.60
        assert result["factors"]["concentration_risk"] == 0.60

    def test_single_point_no_dependency(self):
        result = score_vendor_profile(
            _make_profile(
                single_point_of_failure=True,
                critical_dependency_percent=0,
            )
        )
        # 0.65 + 0.35 * 0.0 = 0.65
        assert result["factors"]["concentration_risk"] == 0.65


class TestPrivilegeScopeRisk:
    @pytest.mark.parametrize(
        "scope,expected",
        [
            ("limited", PRIVILEGE_RISK["limited"]),
            ("moderate", PRIVILEGE_RISK["moderate"]),
            ("admin", PRIVILEGE_RISK["admin"]),
            ("domain_admin", PRIVILEGE_RISK["domain_admin"]),
        ],
    )
    def test_known_scopes(self, scope, expected):
        result = score_vendor_profile(_make_profile(privilege_scope=scope))
        assert result["factors"]["privilege_scope_risk"] == expected

    def test_unknown_scope_defaults(self):
        result = score_vendor_profile(_make_profile(privilege_scope="unknown"))
        assert result["factors"]["privilege_scope_risk"] == 0.45


class TestDataSensitivityRisk:
    @pytest.mark.parametrize(
        "level,expected",
        [
            ("low", DATA_SENSITIVITY_RISK["low"]),
            ("moderate", DATA_SENSITIVITY_RISK["moderate"]),
            ("high", DATA_SENSITIVITY_RISK["high"]),
            ("critical", DATA_SENSITIVITY_RISK["critical"]),
        ],
    )
    def test_known_levels(self, level, expected):
        result = score_vendor_profile(_make_profile(data_sensitivity=level))
        assert result["factors"]["data_exposure_risk"] == expected

    def test_unknown_level_defaults(self):
        result = score_vendor_profile(_make_profile(data_sensitivity="unknown"))
        assert result["factors"]["data_exposure_risk"] == 0.45


class TestCompliancePostureRisk:
    @pytest.mark.parametrize(
        "posture,expected",
        [
            ("strong", COMPLIANCE_RISK["strong"]),
            ("adequate", COMPLIANCE_RISK["adequate"]),
            ("gaps", COMPLIANCE_RISK["gaps"]),
            ("material_findings", COMPLIANCE_RISK["material_findings"]),
        ],
    )
    def test_known_postures(self, posture, expected):
        result = score_vendor_profile(_make_profile(compliance_posture=posture))
        assert result["factors"]["compliance_posture_risk"] == expected

    def test_unknown_posture_defaults(self):
        result = score_vendor_profile(_make_profile(compliance_posture="unknown"))
        assert result["factors"]["compliance_posture_risk"] == 0.35


# ---------------------------------------------------------------------------
# score_vendor_profile integration
# ---------------------------------------------------------------------------


class TestScoreVendorProfile:
    def test_output_keys(self):
        result = score_vendor_profile(_make_profile())
        for key in (
            "profile_id",
            "vendor_name",
            "country",
            "vendor_domain",
            "expected_label",
            "factors",
            "reason_codes",
            "vendor_risk_score",
            "risk_tier",
            "raw_profile",
        ):
            assert key in result, f"Missing key: {key}"

    def test_factors_keys(self):
        result = score_vendor_profile(_make_profile())
        for key in VENDOR_WEIGHTS:
            assert key in result["factors"]

    def test_score_range(self):
        result = score_vendor_profile(_make_profile())
        assert 0.0 <= result["vendor_risk_score"] <= 100.0

    def test_low_risk_vendor(self):
        profile = _make_profile(
            country="US",
            privilege_scope="limited",
            data_sensitivity="low",
            compliance_posture="strong",
            critical_dependency_percent=5,
            single_point_of_failure=False,
            recent_incidents=0,
        )
        result = score_vendor_profile(profile)
        assert result["risk_tier"] == "LOW"
        assert result["vendor_risk_score"] < 40.0

    def test_high_risk_vendor(self):
        profile = _make_profile(
            country="KP",
            privilege_scope="domain_admin",
            data_sensitivity="critical",
            compliance_posture="material_findings",
            critical_dependency_percent=100,
            single_point_of_failure=True,
            recent_incidents=4,
        )
        result = score_vendor_profile(profile)
        assert result["risk_tier"] == "HIGH"
        assert result["vendor_risk_score"] >= 80.0

    def test_incident_modifier_capped(self):
        """Incident modifier should cap at 10.0 points."""
        base = score_vendor_profile(_make_profile(recent_incidents=0))
        maxed = score_vendor_profile(_make_profile(recent_incidents=10))
        diff = maxed["vendor_risk_score"] - base["vendor_risk_score"]
        assert diff == pytest.approx(10.0, abs=0.01)

    def test_negative_incidents_treated_as_zero(self):
        result = score_vendor_profile(_make_profile(recent_incidents=-5))
        base = score_vendor_profile(_make_profile(recent_incidents=0))
        assert result["vendor_risk_score"] == base["vendor_risk_score"]

    def test_score_never_exceeds_100(self):
        profile = _make_profile(
            country="KP",
            privilege_scope="domain_admin",
            data_sensitivity="critical",
            compliance_posture="material_findings",
            critical_dependency_percent=100,
            single_point_of_failure=True,
            recent_incidents=100,
        )
        result = score_vendor_profile(profile)
        assert result["vendor_risk_score"] <= 100.0

    def test_vendor_domain_lowered(self):
        result = score_vendor_profile(_make_profile(vendor_domain="EXAMPLE.COM"))
        assert result["vendor_domain"] == "example.com"

    def test_country_uppercased(self):
        result = score_vendor_profile(_make_profile(country="gb"))
        assert result["country"] == "GB"

    def test_profile_id_stripped(self):
        result = score_vendor_profile(_make_profile(profile_id="  V-099 "))
        assert result["profile_id"] == "V-099"

    def test_raw_profile_preserved(self):
        p = _make_profile()
        result = score_vendor_profile(p)
        assert result["raw_profile"] is p


# ---------------------------------------------------------------------------
# Edge cases: missing or empty fields
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_profile(self):
        """An entirely empty dict should not raise."""
        result = score_vendor_profile({})
        assert result["profile_id"] == ""
        assert result["vendor_name"] == ""
        assert 0.0 <= result["vendor_risk_score"] <= 100.0

    def test_none_values(self):
        profile = {
            "profile_id": None,
            "vendor_name": None,
            "country": None,
            "privilege_scope": None,
            "data_sensitivity": None,
            "compliance_posture": None,
            "critical_dependency_percent": None,
            "single_point_of_failure": None,
            "recent_incidents": None,
        }
        result = score_vendor_profile(profile)
        assert result["profile_id"] == ""
        assert result["vendor_name"] == ""
        assert 0.0 <= result["vendor_risk_score"] <= 100.0

    def test_missing_dependency_percent(self):
        profile = _make_profile()
        del profile["critical_dependency_percent"]
        result = score_vendor_profile(profile)
        # _safe_float(None) => 0.0, so dependency_pct = 0.0
        assert result["factors"]["concentration_risk"] == 0.25

    def test_expected_label_passthrough(self):
        result = score_vendor_profile(_make_profile(expected_label="HIGH"))
        assert result["expected_label"] == "high"


# ---------------------------------------------------------------------------
# Factor decomposition output structure
# ---------------------------------------------------------------------------


class TestFactorDecomposition:
    def test_all_factors_are_floats(self):
        result = score_vendor_profile(_make_profile())
        for k, v in result["factors"].items():
            assert isinstance(v, float), f"{k} should be float, got {type(v)}"

    def test_all_factors_between_zero_and_one(self):
        result = score_vendor_profile(_make_profile())
        for k, v in result["factors"].items():
            assert 0.0 <= v <= 1.0, f"{k}={v} out of [0,1] range"

    def test_weights_sum_to_one(self):
        assert sum(VENDOR_WEIGHTS.values()) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# upsert_supply_chain_assessments (real SQLite)
# ---------------------------------------------------------------------------


class TestUpsertSupplyChainAssessments:
    @pytest.fixture
    def db(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        _supply_chain_table(conn)
        yield conn
        conn.close()

    def test_insert_single(self, db):
        scored = score_vendor_profile(_make_profile(profile_id="V-001"))
        upsert_supply_chain_assessments(db, [scored])
        db.commit()
        row = db.execute(
            "SELECT * FROM supply_chain_risk_assessments WHERE profile_id='V-001'"
        ).fetchone()
        assert row is not None
        assert row["vendor_name"] == "Acme Corp"
        assert row["risk_tier"] in ("LOW", "GUARDED", "ELEVATED", "HIGH")

    def test_insert_multiple(self, db):
        profiles = [
            score_vendor_profile(_make_profile(profile_id="V-010", vendor_name="Alpha")),
            score_vendor_profile(_make_profile(profile_id="V-020", vendor_name="Beta")),
        ]
        upsert_supply_chain_assessments(db, profiles)
        db.commit()
        count = db.execute("SELECT COUNT(*) as c FROM supply_chain_risk_assessments").fetchone()[
            "c"
        ]
        assert count == 2

    def test_upsert_updates_existing(self, db):
        scored_v1 = score_vendor_profile(_make_profile(profile_id="V-001", country="US"))
        upsert_supply_chain_assessments(db, [scored_v1])
        db.commit()

        scored_v2 = score_vendor_profile(_make_profile(profile_id="V-001", country="KP"))
        upsert_supply_chain_assessments(db, [scored_v2])
        db.commit()

        rows = db.execute(
            "SELECT * FROM supply_chain_risk_assessments WHERE profile_id='V-001'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["country"] == "KP"

    def test_reason_codes_stored_as_json(self, db):
        scored = score_vendor_profile(_make_profile(profile_id="V-JSON"))
        upsert_supply_chain_assessments(db, [scored])
        db.commit()
        row = db.execute(
            "SELECT reason_codes_json FROM supply_chain_risk_assessments WHERE profile_id='V-JSON'"
        ).fetchone()
        parsed = json.loads(row["reason_codes_json"])
        assert isinstance(parsed, list)

    def test_factor_breakdown_stored_as_json(self, db):
        scored = score_vendor_profile(_make_profile(profile_id="V-FB"))
        upsert_supply_chain_assessments(db, [scored])
        db.commit()
        row = db.execute(
            "SELECT factor_breakdown_json FROM supply_chain_risk_assessments WHERE profile_id='V-FB'"
        ).fetchone()
        parsed = json.loads(row["factor_breakdown_json"])
        assert isinstance(parsed, dict)
        assert "geographic_risk" in parsed

    def test_empty_list_is_noop(self, db):
        upsert_supply_chain_assessments(db, [])
        count = db.execute("SELECT COUNT(*) as c FROM supply_chain_risk_assessments").fetchone()[
            "c"
        ]
        assert count == 0

    def test_vendor_risk_score_stored_as_float(self, db):
        scored = score_vendor_profile(_make_profile(profile_id="V-FLT"))
        upsert_supply_chain_assessments(db, [scored])
        db.commit()
        row = db.execute(
            "SELECT vendor_risk_score FROM supply_chain_risk_assessments WHERE profile_id='V-FLT'"
        ).fetchone()
        assert isinstance(row["vendor_risk_score"], float)
