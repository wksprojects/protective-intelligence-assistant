from database.init_db import get_connection


def test_acled_first_run_source_registration_survives_keyword_early_return(client, monkeypatch):
    """First-run source INSERT must be committed even when no keywords are active.

    Regression: the early `return 0` on the no-active-keywords path used to skip
    conn.commit(), so the freshly inserted ACLED source row was rolled back by
    conn.close() in the finally block.
    """
    from scraper.acled_connector import run_acled_collector

    monkeypatch.setenv("ACLED_API_KEY", "test-key")
    monkeypatch.setenv("ACLED_EMAIL", "analyst@example.org")

    conn = get_connection()
    conn.execute("DELETE FROM sources WHERE url = ?", ("https://acleddata.com",))
    conn.execute("UPDATE keywords SET active = 0")
    conn.commit()
    conn.close()

    created = run_acled_collector()
    assert created == 0

    conn = get_connection()
    row = conn.execute(
        "SELECT source_type, credibility_score FROM sources WHERE url = ?",
        ("https://acleddata.com",),
    ).fetchone()
    conn.close()

    assert row is not None
    assert row["source_type"] == "acled"
    assert row["credibility_score"] == 0.8
