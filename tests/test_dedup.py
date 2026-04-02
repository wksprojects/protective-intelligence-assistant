"""Unit tests for analytics.dedup — content deduplication engine."""

import hashlib
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from analytics.dedup import (
    check_duplicate,
    compute_content_hash,
    find_content_hash_duplicate,
    find_fuzzy_title_duplicate,
    normalize_text,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_db():
    """Create an in-memory SQLite DB with the alerts table."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            content_hash TEXT,
            duplicate_of INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    return conn


def _insert_alert(
    conn, title, content="body", content_hash=None, duplicate_of=None, created_at=None
):
    """Insert a test alert and return its id."""
    if content_hash is None:
        content_hash = compute_content_hash(title, content)
    sql = (
        "INSERT INTO alerts (title, content, content_hash, duplicate_of, created_at) "
        "VALUES (?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))"
    )
    cur = conn.execute(sql, (title, content, content_hash, duplicate_of, created_at))
    conn.commit()
    return cur.lastrowid


# ===========================================================================
# normalize_text
# ===========================================================================


class TestNormalizeText:
    def test_strips_html_tags(self):
        assert normalize_text("<b>hello</b> <i>world</i>") == "hello world"

    def test_lowercases(self):
        assert normalize_text("HELLO World") == "hello world"

    def test_collapses_whitespace(self):
        assert normalize_text("  a   b\n\tc  ") == "a b c"

    def test_truncates_to_200_chars(self):
        long_text = "a" * 500
        assert len(normalize_text(long_text)) == 200

    def test_empty_string(self):
        assert normalize_text("") == ""

    def test_none_value(self):
        assert normalize_text(None) == ""

    def test_html_with_nested_tags(self):
        result = normalize_text("<div><p>nested</p></div>")
        assert "nested" in result
        assert "<" not in result


# ===========================================================================
# compute_content_hash
# ===========================================================================


class TestComputeContentHash:
    def test_deterministic(self):
        h1 = compute_content_hash("Title", "Content")
        h2 = compute_content_hash("Title", "Content")
        assert h1 == h2

    def test_different_for_different_content(self):
        h1 = compute_content_hash("Title A", "Content A")
        h2 = compute_content_hash("Title B", "Content B")
        assert h1 != h2

    def test_returns_valid_sha256_hex(self):
        h = compute_content_hash("t", "c")
        assert len(h) == 64
        int(h, 16)  # should not raise

    def test_none_title_and_content(self):
        h = compute_content_hash(None, None)
        expected = hashlib.sha256(normalize_text(" ").encode("utf-8")).hexdigest()
        assert h == expected

    def test_empty_strings(self):
        h = compute_content_hash("", "")
        assert isinstance(h, str) and len(h) == 64

    def test_very_long_content_still_produces_hash(self):
        h = compute_content_hash("t" * 1000, "c" * 10000)
        assert len(h) == 64


# ===========================================================================
# find_content_hash_duplicate
# ===========================================================================


class TestFindContentHashDuplicate:
    def test_finds_exact_match(self):
        conn = _make_db()
        chash = compute_content_hash("Breaking news", "Full story here")
        alert_id = _insert_alert(conn, "Breaking news", "Full story here", content_hash=chash)
        assert find_content_hash_duplicate(conn, chash) == alert_id

    def test_returns_none_when_no_match(self):
        conn = _make_db()
        _insert_alert(conn, "Some alert", "body")
        assert find_content_hash_duplicate(conn, "0" * 64) is None

    def test_skips_duplicates_themselves(self):
        """Alerts already marked as duplicate_of should not be returned."""
        conn = _make_db()
        chash = compute_content_hash("Alert", "Body")
        original_id = _insert_alert(conn, "Alert", "Body", content_hash=chash)
        _insert_alert(conn, "Alert", "Body", content_hash=chash, duplicate_of=original_id)
        result = find_content_hash_duplicate(conn, chash)
        assert result == original_id

    def test_empty_table(self):
        conn = _make_db()
        assert find_content_hash_duplicate(conn, "abc123" + "0" * 58) is None


# ===========================================================================
# find_fuzzy_title_duplicate
# ===========================================================================


class TestFindFuzzyTitleDuplicate:
    def _patch_utcnow(self):
        """Return a patch that makes utcnow() return a fixed datetime."""
        from datetime import datetime

        fixed = datetime(2025, 6, 15, 12, 0, 0)
        return patch("analytics.utils.utcnow", return_value=fixed)

    def _insert_today(self, conn, title, content="body"):
        """Insert an alert with created_at set to the patched 'today'."""
        return _insert_alert(conn, title, content, created_at="2025-06-15 10:00:00")

    def test_finds_similar_title(self):
        conn = _make_db()
        with self._patch_utcnow():
            alert_id = self._insert_today(conn, "Threat actor spotted near embassy")
            result = find_fuzzy_title_duplicate(conn, "Threat actor spotted near the embassy")
        assert result == alert_id

    def test_returns_none_for_dissimilar_titles(self):
        conn = _make_db()
        with self._patch_utcnow():
            self._insert_today(conn, "Weather forecast for tomorrow")
            result = find_fuzzy_title_duplicate(conn, "New cybersecurity vulnerability found")
        assert result is None

    def test_returns_none_for_empty_title(self):
        conn = _make_db()
        assert find_fuzzy_title_duplicate(conn, "") is None
        assert find_fuzzy_title_duplicate(conn, None) is None

    def test_respects_threshold(self):
        conn = _make_db()
        with self._patch_utcnow():
            self._insert_today(conn, "Alpha bravo charlie")
            # With a very high threshold, a slightly different title should not match.
            result = find_fuzzy_title_duplicate(conn, "Alpha bravo delta", threshold=0.99)
        assert result is None

    def test_picks_best_match(self):
        conn = _make_db()
        with self._patch_utcnow():
            self._insert_today(conn, "Suspicious activity near building A")
            better_id = self._insert_today(conn, "Suspicious activity near building B zone")
            result = find_fuzzy_title_duplicate(
                conn, "Suspicious activity near building B zone area"
            )
        assert result == better_id

    def test_max_candidates_limits_query(self):
        conn = _make_db()
        with self._patch_utcnow():
            for i in range(10):
                self._insert_today(conn, f"Alert number {i}")
            # Only look at 3 most recent (ids 8,9,10 — "Alert number 7/8/9")
            result = find_fuzzy_title_duplicate(conn, "Alert number 9", max_candidates=3)
            assert result is not None

    def test_skips_alerts_marked_as_duplicates(self):
        conn = _make_db()
        with self._patch_utcnow():
            original = self._insert_today(conn, "Important security alert")
            _insert_alert(
                conn,
                "Important security alert",
                created_at="2025-06-15 10:00:00",
                duplicate_of=original,
            )
            result = find_fuzzy_title_duplicate(conn, "Important security alert")
        assert result == original


# ===========================================================================
# check_duplicate (integration)
# ===========================================================================


class TestCheckDuplicate:
    def _patch_utcnow(self):
        from datetime import datetime

        fixed = datetime(2025, 6, 15, 12, 0, 0)
        return patch("analytics.utils.utcnow", return_value=fixed)

    def test_detects_exact_hash_duplicate(self):
        conn = _make_db()
        title, content = "Same title", "Same content"
        _insert_alert(conn, title, content)
        with self._patch_utcnow():
            content_hash, dup_id = check_duplicate(conn, title, content)
        assert dup_id is not None
        assert len(content_hash) == 64

    def test_detects_fuzzy_duplicate(self):
        conn = _make_db()
        _insert_alert(
            conn,
            "Suspicious package found outside office",
            "completely different body so hash won't match",
            created_at="2025-06-15 08:00:00",
        )
        with self._patch_utcnow():
            _, dup_id = check_duplicate(
                conn,
                "Suspicious package found outside the office",
                "unique content so hash path misses",
            )
        assert dup_id is not None

    def test_returns_none_for_unique_alert(self):
        conn = _make_db()
        with self._patch_utcnow():
            content_hash, dup_id = check_duplicate(conn, "Totally new alert", "New body")
        assert dup_id is None
        assert len(content_hash) == 64

    def test_hash_path_takes_priority(self):
        """If the hash matches, fuzzy path should not even be needed."""
        conn = _make_db()
        title, content = "Alert X", "Body X"
        original_id = _insert_alert(conn, title, content, created_at="2025-06-15 08:00:00")
        with self._patch_utcnow():
            _, dup_id = check_duplicate(conn, title, content)
        assert dup_id == original_id
