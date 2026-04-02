import logging

from scraper.darkweb_collector import run_darkweb_collector


def test_darkweb_collector_skips_when_disabled(monkeypatch, caplog):
    monkeypatch.delenv("PI_ENABLE_DARKWEB_COLLECTOR", raising=False)

    with caplog.at_level(logging.INFO, logger="scraper.darkweb_collector"):
        result = run_darkweb_collector()

    assert result == 0
    assert "skipped" in caplog.text.lower()


def test_darkweb_collector_enabled_is_explicit_noop(monkeypatch, caplog):
    monkeypatch.setenv("PI_ENABLE_DARKWEB_COLLECTOR", "1")

    with caplog.at_level(logging.WARNING, logger="scraper.darkweb_collector"):
        result = run_darkweb_collector()

    assert result == 0
    assert "not implemented" in caplog.text.lower()
