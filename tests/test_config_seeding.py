from pathlib import Path
from textwrap import dedent

from database import init_db as db_init


def _write_watchlist(path: Path, content: str):
    path.write_text(dedent(content).strip() + "\n", encoding="utf-8")


def test_seed_default_sources_prefers_yaml_and_upserts_by_url(tmp_path, monkeypatch):
    db_path = tmp_path / "sources_seed.db"
    watchlist_path = tmp_path / "watchlist.yaml"

    monkeypatch.setattr(db_init, "DB_PATH", str(db_path))
    monkeypatch.setattr(db_init, "WATCHLIST_CONFIG_PATH", str(watchlist_path))

    _write_watchlist(
        watchlist_path,
        """
        sources:
          rss:
            - name: "Custom Feed A"
              url: "https://example.com/feed.xml"
        keywords: {}
        """,
    )

    db_init.init_db()
    db_init.migrate_schema()
    db_init.seed_default_sources()

    conn = db_init.get_connection()
    rows = conn.execute("SELECT name, url, source_type FROM sources ORDER BY id").fetchall()
    assert len(rows) == 1
    assert rows[0]["name"] == "Custom Feed A"
    assert rows[0]["url"] == "https://example.com/feed.xml"
    assert rows[0]["source_type"] == "rss"
    conn.close()

    _write_watchlist(
        watchlist_path,
        """
        sources:
          reddit:
            - name: "Custom Feed B"
              url: "https://example.com/feed.xml"
        keywords: {}
        """,
    )
    db_init.seed_default_sources()

    conn = db_init.get_connection()
    rows = conn.execute(
        "SELECT name, url, source_type, credibility_score FROM sources ORDER BY id"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["name"] == "Custom Feed B"
    assert rows[0]["url"] == "https://example.com/feed.xml"
    assert rows[0]["source_type"] == "reddit"
    assert rows[0]["credibility_score"] == 0.5
    conn.close()


def test_seed_default_keywords_prefers_yaml_and_upserts_by_term(tmp_path, monkeypatch):
    db_path = tmp_path / "keywords_seed.db"
    watchlist_path = tmp_path / "watchlist.yaml"

    monkeypatch.setattr(db_init, "DB_PATH", str(db_path))
    monkeypatch.setattr(db_init, "WATCHLIST_CONFIG_PATH", str(watchlist_path))

    _write_watchlist(
        watchlist_path,
        """
        keywords:
          malware:
            - "CustomTerm"
        sources: {}
        """,
    )

    db_init.init_db()
    db_init.migrate_schema()
    db_init.seed_default_keywords()

    conn = db_init.get_connection()
    rows = conn.execute("SELECT term, category, weight FROM keywords ORDER BY id").fetchall()
    assert len(rows) == 1
    assert rows[0]["term"] == "CustomTerm"
    assert rows[0]["category"] == "malware"
    assert rows[0]["weight"] == 1.0
    conn.close()

    _write_watchlist(
        watchlist_path,
        """
        keywords:
          general:
            - "CustomTerm"
        sources: {}
        """,
    )
    db_init.seed_default_keywords()

    conn = db_init.get_connection()
    rows = conn.execute("SELECT term, category, weight FROM keywords ORDER BY id").fetchall()
    assert len(rows) == 1
    assert rows[0]["term"] == "CustomTerm"
    assert rows[0]["category"] == "general"
    assert rows[0]["weight"] == 1.0
    conn.close()


def test_seed_default_sources_supports_darkweb_yaml_block(tmp_path, monkeypatch):
    db_path = tmp_path / "darkweb_seed.db"
    watchlist_path = tmp_path / "watchlist.yaml"

    monkeypatch.setattr(db_init, "DB_PATH", str(db_path))
    monkeypatch.setattr(db_init, "WATCHLIST_CONFIG_PATH", str(watchlist_path))

    _write_watchlist(
        watchlist_path,
        """
        sources:
          darkweb:
            - name: "Onion Index Alpha"
              url: "http://exampleonionaddress.onion/search?q=stalking"
        keywords: {}
        """,
    )

    db_init.init_db()
    db_init.migrate_schema()
    db_init.seed_default_sources()

    conn = db_init.get_connection()
    row = conn.execute(
        "SELECT name, url, source_type, credibility_score FROM sources ORDER BY id LIMIT 1"
    ).fetchone()
    conn.close()

    assert row is not None
    assert row["name"] == "Onion Index Alpha"
    assert row["url"] == "http://exampleonionaddress.onion/search?q=stalking"
    assert row["source_type"] == "darkweb"
    assert row["credibility_score"] == db_init.SOURCE_DEFAULT_CREDIBILITY["darkweb"]


def test_seed_default_keywords_respects_explicit_weight(tmp_path, monkeypatch):
    db_path = tmp_path / "keywords_weighted_seed.db"
    watchlist_path = tmp_path / "watchlist.yaml"

    monkeypatch.setattr(db_init, "DB_PATH", str(db_path))
    monkeypatch.setattr(db_init, "WATCHLIST_CONFIG_PATH", str(watchlist_path))

    _write_watchlist(
        watchlist_path,
        """
        keywords:
          protective_intel:
            - term: "death threat"
              weight: 5.0
        sources: {}
        """,
    )

    db_init.init_db()
    db_init.migrate_schema()
    db_init.seed_default_keywords()

    conn = db_init.get_connection()
    row = conn.execute(
        "SELECT term, category, weight FROM keywords WHERE term = ?",
        ("death threat",),
    ).fetchone()
    assert row is not None
    assert row["category"] == "protective_intel"
    assert row["weight"] == 5.0
    conn.close()


def test_seed_default_keywords_uses_poi_default_weight(tmp_path, monkeypatch):
    db_path = tmp_path / "keywords_poi_default.db"
    watchlist_path = tmp_path / "watchlist.yaml"

    monkeypatch.setattr(db_init, "DB_PATH", str(db_path))
    monkeypatch.setattr(db_init, "WATCHLIST_CONFIG_PATH", str(watchlist_path))

    _write_watchlist(
        watchlist_path,
        """
        keywords:
          poi:
            - "Jane Doe"
        sources: {}
        """,
    )

    db_init.init_db()
    db_init.migrate_schema()
    db_init.seed_default_keywords()

    conn = db_init.get_connection()
    row = conn.execute(
        "SELECT term, category, weight FROM keywords WHERE term = ?",
        ("Jane Doe",),
    ).fetchone()
    conn.close()
    assert row is not None
    assert row["category"] == "poi"
    assert row["weight"] == 4.0


def test_seed_default_sources_includes_pi_ep_feeds_from_default_watchlist(tmp_path, monkeypatch):
    db_path = tmp_path / "pi_ep_seed.db"
    monkeypatch.setattr(db_init, "DB_PATH", str(db_path))

    db_init.init_db()
    db_init.migrate_schema()
    db_init.seed_default_sources()

    conn = db_init.get_connection()
    rows = conn.execute(
        "SELECT name, url FROM sources WHERE source_type = 'rss' AND active = 1"
    ).fetchall()
    conn.close()
    urls = {row["url"] for row in rows}
    by_name = {row["name"]: row["url"] for row in rows}

    assert "https://travel.state.gov/_res/rss/TAsTWs.xml" in urls
    assert "https://www.who.int/feeds/entity/csr/don/en/rss.xml" in urls
    assert "https://wwwnc.cdc.gov/travel/rss/notices.xml" in urls
    assert "GDELT PI/EP Watch" in by_name
    assert by_name["GDELT PI/EP Watch"] == db_init.build_gdelt_rss_url(
        db_init.DEFAULT_GDELT_PI_EP_QUERY
    )


def test_build_gdelt_rss_url_encodes_query():
    url = db_init.build_gdelt_rss_url('("death threat" OR swatting) AND CEO')
    assert url.startswith("https://api.gdeltproject.org/api/v2/doc/doc?")
    assert "mode=artlist" in url
    assert "format=rss" in url
    assert "timespan=24h" in url
    assert "maxrecords=100" in url
    assert "sort=datedesc" in url
    assert "query=%28%22death+threat%22+OR+swatting%29+AND+CEO" in url
