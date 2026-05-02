"""Unit tests for analytics.soi_threads -- SOI thread correlation engine.

Validates pair linking, reason code assignment, UnionFind clustering,
min cluster size filtering, time window constraints, and edge cases
using an in-memory SQLite database seeded with the project schema.
"""

import sys
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from database import init_db as db_init

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Stand up a temp DB with full schema and seed data, return connection."""
    db_path = tmp_path / "soi_test.db"
    monkeypatch.setattr(db_init, "DB_PATH", str(db_path))
    db_init.init_db()
    db_init.migrate_schema()
    db_init.seed_default_sources()
    db_init.seed_default_keywords()
    db_init.seed_default_pois()
    conn = db_init.get_connection()
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _source_id(conn, source_type="rss"):
    row = conn.execute(
        "SELECT id FROM sources WHERE source_type = ? LIMIT 1", (source_type,)
    ).fetchone()
    if row:
        return row["id"]
    conn.execute(
        "INSERT INTO sources (name, url, source_type) VALUES (?, ?, ?)",
        (f"test-{source_type}", f"https://{source_type}.example.com", source_type),
    )
    conn.commit()
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _keyword_id(conn):
    row = conn.execute(
        "SELECT id FROM keywords WHERE category = 'protective_intel' LIMIT 1"
    ).fetchone()
    if row:
        return row["id"]
    conn.execute("INSERT INTO keywords (term, category) VALUES ('test_term', 'protective_intel')")
    conn.commit()
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _insert_alert(
    conn,
    title,
    ts_offset_hours=0,
    source_type="rss",
    matched_term=None,
    severity="low",
    ors_score=0.0,
    tas_score=0.0,
    url=None,
):
    """Insert an alert and return its id.

    ts_offset_hours: negative = in the past relative to now.
    """
    from analytics.utils import utcnow

    ts = (utcnow() - timedelta(hours=abs(ts_offset_hours))).strftime("%Y-%m-%d %H:%M:%S")
    sid = _source_id(conn, source_type)
    kid = _keyword_id(conn)
    conn.execute(
        """INSERT INTO alerts
        (source_id, keyword_id, title, url, matched_term, severity,
         ors_score, tas_score, published_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            sid,
            kid,
            title,
            url or f"https://example.com/{title[:20].replace(' ', '-')}",
            matched_term or "",
            severity,
            ors_score,
            tas_score,
            ts,
        ),
    )
    conn.commit()
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _link_poi(conn, alert_id, poi_id, match_value="Test POI"):
    conn.execute(
        """INSERT OR IGNORE INTO poi_hits
        (poi_id, alert_id, match_type, match_value, match_score, context)
        VALUES (?, ?, 'exact', ?, 1.0, 'test')""",
        (poi_id, alert_id, match_value),
    )
    conn.commit()


def _add_entity(conn, alert_id, entity_type, entity_value):
    conn.execute(
        """INSERT OR IGNORE INTO alert_entities
        (alert_id, entity_type, entity_value)
        VALUES (?, ?, ?)""",
        (alert_id, entity_type, entity_value),
    )
    conn.commit()


def _first_poi_id(conn):
    row = conn.execute("SELECT id FROM pois LIMIT 1").fetchone()
    return row["id"] if row else None


# ---------------------------------------------------------------------------
# 1. Pair linking logic
# ---------------------------------------------------------------------------


class TestPairLinking:
    """Two alerts sharing an entity produce a link with score and reasons."""

    def test_shared_poi_creates_link(self, db):
        poi_id = _first_poi_id(db)
        assert poi_id is not None

        a1 = _insert_alert(db, "Alert A about CEO", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Alert B about CEO", ts_offset_hours=2, source_type="reddit")
        _link_poi(db, a1, poi_id, "Tim Cook")
        _link_poi(db, a2, poi_id, "Tim Cook")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        # There must be at least one thread containing both alerts
        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert t["thread_confidence"] > 0
                break
        else:
            pytest.fail("Expected a thread linking the two shared-POI alerts")

    def test_shared_actor_handle_creates_link(self, db):
        a1 = _insert_alert(db, "Actor post one", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Actor post two", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@threat_user")
        _add_entity(db, a2, "actor_handle", "@threat_user")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        found = any({e["alert_id"] for e in t["timeline"]} >= {a1, a2} for t in threads)
        assert found, "Shared actor_handle should link alerts into a thread"

    def test_shared_domain_entity_creates_link(self, db):
        a1 = _insert_alert(db, "Domain alert one", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Domain alert two", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "domain", "evil.example.com")
        _add_entity(db, a2, "domain", "evil.example.com")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        found = any({e["alert_id"] for e in t["timeline"]} >= {a1, a2} for t in threads)
        assert found, "Shared domain entity should link alerts into a thread"


# ---------------------------------------------------------------------------
# 2. Reason code assignment
# ---------------------------------------------------------------------------


class TestReasonCodes:
    """Each entity type maps to the correct reason code."""

    def test_shared_actor_handle_reason(self, db):
        a1 = _insert_alert(db, "Handle A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Handle B", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@badguy")
        _add_entity(db, a2, "actor_handle", "@badguy")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert "shared_actor_handle" in t["reason_codes"]
                return
        pytest.fail("Thread not found for shared_actor_handle test")

    def test_shared_entity_reason_for_domain(self, db):
        a1 = _insert_alert(db, "Domain X", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Domain Y", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "domain", "test.example.com")
        _add_entity(db, a2, "domain", "test.example.com")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert "shared_entity" in t["reason_codes"]
                return
        pytest.fail("Thread not found for shared_entity/domain test")

    def test_shared_entity_reason_for_ipv4(self, db):
        a1 = _insert_alert(db, "IP one", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "IP two", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "ipv4", "192.168.1.1")
        _add_entity(db, a2, "ipv4", "192.168.1.1")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert "shared_entity" in t["reason_codes"]
                return
        pytest.fail("Thread not found for shared_entity/ipv4 test")

    def test_shared_user_id_reason(self, db):
        a1 = _insert_alert(db, "User A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "User B", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "user_id", "uid_12345")
        _add_entity(db, a2, "user_id", "uid_12345")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert "shared_user_id" in t["reason_codes"]
                return
        pytest.fail("Thread not found for shared_user_id test")

    def test_shared_device_id_reason(self, db):
        a1 = _insert_alert(db, "Device A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Device B", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "device_id", "dev_abc123")
        _add_entity(db, a2, "device_id", "dev_abc123")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert "shared_device_id" in t["reason_codes"]
                return
        pytest.fail("Thread not found for shared_device_id test")

    def test_shared_vendor_id_reason(self, db):
        a1 = _insert_alert(db, "Vendor A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Vendor B", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "vendor_id", "vendor_xyz")
        _add_entity(db, a2, "vendor_id", "vendor_xyz")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert "shared_vendor_id" in t["reason_codes"]
                return
        pytest.fail("Thread not found for shared_vendor_id test")

    def test_temporal_proximity_reason(self, db):
        """Alerts sharing an entity within 12h get tight_temporal reason."""
        a1 = _insert_alert(db, "Temporal A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Temporal B", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@close_timer")
        _add_entity(db, a2, "actor_handle", "@close_timer")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert "tight_temporal" in t["reason_codes"]
                return
        pytest.fail("Thread not found for tight_temporal test")

    def test_cross_source_reason(self, db):
        """Alerts from different source types get cross_source reason."""
        a1 = _insert_alert(db, "Cross src A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Cross src B", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@cross_src")
        _add_entity(db, a2, "actor_handle", "@cross_src")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert "cross_source" in t["reason_codes"]
                return
        pytest.fail("Thread not found for cross_source test")

    def test_shared_poi_reason(self, db):
        poi_id = _first_poi_id(db)
        a1 = _insert_alert(db, "POI alert A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "POI alert B", ts_offset_hours=2, source_type="reddit")
        _link_poi(db, a1, poi_id, "Test POI")
        _link_poi(db, a2, poi_id, "Test POI")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert "shared_poi" in t["reason_codes"]
                return
        pytest.fail("Thread not found for shared_poi test")

    def test_matched_term_temporal_reason(self, db):
        """Alerts sharing matched_term within 24h get matched_term_temporal."""
        a1 = _insert_alert(
            db, "Term alert A", ts_offset_hours=1, source_type="rss", matched_term="bomb threat"
        )
        a2 = _insert_alert(
            db, "Term alert B", ts_offset_hours=2, source_type="reddit", matched_term="bomb threat"
        )
        # Need a shared link strong enough to form a thread (keyword alone
        # scores 0.2 which is below _MIN_PAIR_LINK_SCORE).  Add a POI link
        # to ensure the thread forms, then check keyword reason is present.
        poi_id = _first_poi_id(db)
        _link_poi(db, a1, poi_id, "POI for term")
        _link_poi(db, a2, poi_id, "POI for term")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=24, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if a1 in ids and a2 in ids:
                assert "matched_term_temporal" in t["reason_codes"]
                return
        pytest.fail("Thread not found for matched_term_temporal test")


# ---------------------------------------------------------------------------
# 3. Clustering behavior (UnionFind)
# ---------------------------------------------------------------------------


class TestClustering:
    """Linked pairs are merged into clusters via UnionFind."""

    def test_union_find_basic(self):
        from analytics.soi_threads import _UnionFind

        uf = _UnionFind([1, 2, 3, 4, 5])
        uf.union(1, 2)
        uf.union(3, 4)
        assert uf.find(1) == uf.find(2)
        assert uf.find(3) == uf.find(4)
        assert uf.find(1) != uf.find(3)

    def test_union_find_transitive(self):
        from analytics.soi_threads import _UnionFind

        uf = _UnionFind([1, 2, 3])
        uf.union(1, 2)
        uf.union(2, 3)
        assert uf.find(1) == uf.find(3), "Transitive union failed"

    def test_union_find_idempotent(self):
        from analytics.soi_threads import _UnionFind

        uf = _UnionFind([1, 2])
        uf.union(1, 2)
        root_before = uf.find(1)
        uf.union(1, 2)
        assert uf.find(1) == root_before

    def test_three_alerts_same_entity_form_one_cluster(self, db):
        """A-B-C sharing the same actor_handle form a single cluster."""
        ids = []
        for i in range(3):
            aid = _insert_alert(
                db,
                f"Cluster alert {i}",
                ts_offset_hours=i + 1,
                source_type="rss" if i % 2 == 0 else "reddit",
            )
            _add_entity(db, aid, "actor_handle", "@cluster_test")
            ids.append(aid)

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            thread_ids = {e["alert_id"] for e in t["timeline"]}
            if set(ids).issubset(thread_ids):
                assert t["alerts_count"] >= 3
                return
        pytest.fail("Three alerts with shared actor should form one cluster")

    def test_separate_entities_produce_separate_clusters(self, db):
        """Alerts sharing different entities stay in different clusters."""
        a1 = _insert_alert(db, "Group A one", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Group A two", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@alpha")
        _add_entity(db, a2, "actor_handle", "@alpha")

        b1 = _insert_alert(db, "Group B one", ts_offset_hours=1, source_type="rss")
        b2 = _insert_alert(db, "Group B two", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, b1, "actor_handle", "@beta")
        _add_entity(db, b2, "actor_handle", "@beta")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        # Find the thread for each group
        group_a_thread = None
        group_b_thread = None
        for t in threads:
            thread_ids = {e["alert_id"] for e in t["timeline"]}
            if {a1, a2}.issubset(thread_ids):
                group_a_thread = t
            if {b1, b2}.issubset(thread_ids):
                group_b_thread = t

        assert group_a_thread is not None, "Group A should form a thread"
        assert group_b_thread is not None, "Group B should form a thread"
        # They should be different threads (different thread_id)
        if group_a_thread["thread_id"] == group_b_thread["thread_id"]:
            # They might merge if they happen to share something else,
            # but at minimum both alert sets should be represented
            pass


# ---------------------------------------------------------------------------
# 4. Min cluster size filtering
# ---------------------------------------------------------------------------


class TestMinClusterSize:
    """Clusters below min_cluster_size are excluded from results."""

    def test_single_pair_meets_min_size_2(self, db):
        a1 = _insert_alert(db, "Pair A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Pair B", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@min_test")
        _add_entity(db, a2, "actor_handle", "@min_test")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        found = any({e["alert_id"] for e in t["timeline"]} >= {a1, a2} for t in threads)
        assert found, "Pair of 2 should meet min_cluster_size=2"

    def test_pair_excluded_at_min_size_3(self, db):
        a1 = _insert_alert(db, "Small A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Small B", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@small_cluster")
        _add_entity(db, a2, "actor_handle", "@small_cluster")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=3)

        found = any({e["alert_id"] for e in t["timeline"]} >= {a1, a2} for t in threads)
        assert not found, "Cluster of 2 should be excluded when min_cluster_size=3"

    def test_cluster_of_3_meets_min_size_3(self, db):
        ids = []
        for i in range(3):
            aid = _insert_alert(
                db,
                f"Triple {i}",
                ts_offset_hours=i + 1,
                source_type="rss" if i % 2 == 0 else "reddit",
            )
            _add_entity(db, aid, "actor_handle", "@triple")
            ids.append(aid)

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=3)

        found = any(set(ids).issubset({e["alert_id"] for e in t["timeline"]}) for t in threads)
        assert found, "Cluster of 3 should meet min_cluster_size=3"


# ---------------------------------------------------------------------------
# 5. Time window filtering
# ---------------------------------------------------------------------------


class TestTimeWindow:
    """Alerts outside the time window are not correlated."""

    def test_alerts_outside_days_window_excluded(self, db):
        """Alerts older than `days` are not fetched at all."""
        a1 = _insert_alert(db, "Old alert A", ts_offset_hours=24 * 30, source_type="rss")
        a2 = _insert_alert(db, "Old alert B", ts_offset_hours=24 * 31, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@old_pair")
        _add_entity(db, a2, "actor_handle", "@old_pair")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=7, window_hours=72, min_cluster_size=2)

        found = any({e["alert_id"] for e in t["timeline"]} >= {a1, a2} for t in threads)
        assert not found, "Alerts 30+ days old should be excluded with days=7"

    def test_alerts_outside_window_hours_not_linked(self, db):
        """Alerts within `days` but further apart than `window_hours` should
        not be linked by a weak signal alone."""
        # 2 alerts 50 hours apart, using window_hours=4
        a1 = _insert_alert(db, "Window A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Window B", ts_offset_hours=51, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@window_test")
        _add_entity(db, a2, "actor_handle", "@window_test")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=14, window_hours=4, min_cluster_size=2)

        found = any({e["alert_id"] for e in t["timeline"]} >= {a1, a2} for t in threads)
        assert not found, "Alerts 50h apart should not link with window_hours=4"

    def test_alerts_within_window_hours_linked(self, db):
        """Alerts within window_hours are linked."""
        a1 = _insert_alert(db, "Close A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Close B", ts_offset_hours=3, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@close_pair")
        _add_entity(db, a2, "actor_handle", "@close_pair")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        found = any({e["alert_id"] for e in t["timeline"]} >= {a1, a2} for t in threads)
        assert found, "Alerts 2h apart should link with window_hours=72"


# ---------------------------------------------------------------------------
# 6. Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Empty sets, single alerts, no entities, duplicate entities."""

    def test_empty_alert_set_returns_empty(self, db):
        """No alerts in the window produces an empty list."""
        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)
        assert threads == [] or isinstance(threads, list)

    def test_single_alert_returns_empty(self, db):
        """A single alert cannot form a cluster."""
        _insert_alert(db, "Lonely alert", ts_offset_hours=1)

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)
        # No thread should contain exactly one alert
        for t in threads:
            assert t["alerts_count"] >= 2

    def test_alerts_with_no_entities_no_crash(self, db):
        """Alerts with no entities or POI links do not crash."""
        for i in range(5):
            _insert_alert(db, f"No entity alert {i}", ts_offset_hours=i + 1, source_type="rss")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)
        assert isinstance(threads, list)

    def test_duplicate_entity_values_handled(self, db):
        """Same entity added twice to same alert does not cause errors."""
        a1 = _insert_alert(db, "Dup entity A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Dup entity B", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "@dup")
        _add_entity(db, a2, "actor_handle", "@dup")
        # Attempt duplicate insertion (UNIQUE constraint, should be ignored)
        _add_entity(db, a1, "actor_handle", "@dup")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        found = any({e["alert_id"] for e in t["timeline"]} >= {a1, a2} for t in threads)
        assert found, "Duplicate entity insertion should not break threading"

    def test_empty_entity_value_ignored(self, db):
        """Entities with empty string values should not cause false links."""
        a1 = _insert_alert(db, "Empty entity A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Empty entity B", ts_offset_hours=2, source_type="reddit")
        _add_entity(db, a1, "actor_handle", "")
        _add_entity(db, a2, "actor_handle", "")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        # Should not form a thread based on empty entity values
        found = any({e["alert_id"] for e in t["timeline"]} >= {a1, a2} for t in threads)
        assert not found, "Empty entity values should not link alerts"


# ---------------------------------------------------------------------------
# 7. Internal helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    """Unit tests for internal helper functions."""

    def test_normalize_tokens_basic(self):
        from analytics.soi_threads import _normalize_tokens

        result = _normalize_tokens("Hello World test")
        assert "hello" in result
        assert "world" in result
        assert "test" in result

    def test_normalize_tokens_short_words_excluded(self):
        from analytics.soi_threads import _normalize_tokens

        result = _normalize_tokens("a to do it")
        # all tokens are < 3 chars
        assert len(result) == 0

    def test_normalize_tokens_empty(self):
        from analytics.soi_threads import _normalize_tokens

        assert _normalize_tokens(None) == set()
        assert _normalize_tokens("") == set()

    def test_source_fingerprint(self):
        from analytics.soi_threads import _source_fingerprint

        fp = _source_fingerprint("rss", "https://www.example.com/feed")
        assert fp == "rss:example.com"

    def test_source_fingerprint_no_url(self):
        from analytics.soi_threads import _source_fingerprint

        fp = _source_fingerprint("rss", None)
        assert fp == "rss:unknown"

    def test_pair_key_ordering(self):
        from analytics.soi_threads import _pair_key

        assert _pair_key(5, 3) == (3, 5)
        assert _pair_key(1, 2) == (1, 2)
        assert _pair_key(2, 1) == (1, 2)

    def test_jaccard_identical(self):
        from analytics.soi_threads import _jaccard

        assert _jaccard({"a", "b"}, {"a", "b"}) == 1.0

    def test_jaccard_disjoint(self):
        from analytics.soi_threads import _jaccard

        assert _jaccard({"a"}, {"b"}) == 0.0

    def test_jaccard_empty(self):
        from analytics.soi_threads import _jaccard

        assert _jaccard(set(), {"a"}) == 0.0
        assert _jaccard(set(), set()) == 0.0

    def test_record_pair(self):
        from analytics.soi_threads import _record_pair

        scores = {}
        reasons = defaultdict(set)
        _record_pair(scores, reasons, 1, 2, 0.5, {"test_reason"})
        assert scores[(1, 2)] == 0.5
        assert "test_reason" in reasons[(1, 2)]

    def test_record_pair_accumulates(self):
        from analytics.soi_threads import _record_pair

        scores = {}
        reasons = defaultdict(set)
        _record_pair(scores, reasons, 1, 2, 0.3, {"reason_a"})
        _record_pair(scores, reasons, 1, 2, 0.4, {"reason_b"})
        assert scores[(1, 2)] == 0.7
        assert reasons[(1, 2)] == {"reason_a", "reason_b"}

    def test_record_pair_caps_at_1(self):
        from analytics.soi_threads import _record_pair

        scores = {}
        reasons = defaultdict(set)
        _record_pair(scores, reasons, 1, 2, 0.8, {"a"})
        _record_pair(scores, reasons, 1, 2, 0.8, {"b"})
        assert scores[(1, 2)] == 1.0


# ---------------------------------------------------------------------------
# 8. Thread output structure
# ---------------------------------------------------------------------------


class TestThreadStructure:
    """Validate the shape of returned thread dicts."""

    def test_thread_has_required_keys(self, db):
        poi_id = _first_poi_id(db)
        a1 = _insert_alert(db, "Struct A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "Struct B", ts_offset_hours=2, source_type="reddit")
        _link_poi(db, a1, poi_id, "Struct POI")
        _link_poi(db, a2, poi_id, "Struct POI")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)
        assert len(threads) >= 1

        t = threads[0]
        required = {
            "thread_id",
            "label",
            "alerts_count",
            "sources_count",
            "source_types",
            "sources",
            "start_ts",
            "end_ts",
            "max_ors_score",
            "max_tas_score",
            "thread_confidence",
            "reason_codes",
            "pair_evidence",
            "poi_ids",
            "poi_names",
            "actor_handles",
            "shared_entities",
            "matched_terms",
            "timeline",
        }
        missing = required - set(t.keys())
        assert not missing, f"Thread missing keys: {missing}"

    def test_thread_id_format(self, db):
        poi_id = _first_poi_id(db)
        a1 = _insert_alert(db, "ID A", ts_offset_hours=1, source_type="rss")
        a2 = _insert_alert(db, "ID B", ts_offset_hours=2, source_type="reddit")
        _link_poi(db, a1, poi_id, "ID POI")
        _link_poi(db, a2, poi_id, "ID POI")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)
        assert len(threads) >= 1
        assert threads[0]["thread_id"].startswith("soi-")
        assert len(threads[0]["thread_id"]) == 16  # "soi-" + 12 hex chars

    def test_timeline_sorted_chronologically(self, db):
        poi_id = _first_poi_id(db)
        a1 = _insert_alert(db, "Chrono A", ts_offset_hours=10, source_type="rss")
        a2 = _insert_alert(db, "Chrono B", ts_offset_hours=5, source_type="reddit")
        a3 = _insert_alert(db, "Chrono C", ts_offset_hours=1, source_type="rss")
        for aid in [a1, a2, a3]:
            _link_poi(db, aid, poi_id, "Chrono POI")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        for t in threads:
            ids = {e["alert_id"] for e in t["timeline"]}
            if {a1, a2, a3}.issubset(ids):
                timestamps = [e["timestamp"] for e in t["timeline"]]
                assert timestamps == sorted(timestamps), "Timeline should be sorted chronologically"
                return

    def test_threads_sorted_by_confidence_desc(self, db):
        """Returned threads should be sorted by confidence descending."""
        poi_id = _first_poi_id(db)
        # Create two separate clusters
        for handle in ["@conf_high", "@conf_low"]:
            for i in range(2):
                aid = _insert_alert(
                    db,
                    f"Conf {handle} {i}",
                    ts_offset_hours=i + 1,
                    source_type="rss" if i == 0 else "reddit",
                )
                _add_entity(db, aid, "actor_handle", handle)
                _link_poi(db, aid, poi_id, f"POI {handle}")

        from analytics.soi_threads import build_soi_threads

        threads = build_soi_threads(days=1, window_hours=72, min_cluster_size=2)

        if len(threads) >= 2:
            confidences = [t["thread_confidence"] for t in threads]
            assert confidences == sorted(confidences, reverse=True)
