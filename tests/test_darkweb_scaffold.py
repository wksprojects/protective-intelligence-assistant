from scraper.darkweb_collector import run_darkweb_collector


def test_darkweb_collector_skips_when_disabled(monkeypatch, capsys):
    monkeypatch.delenv("PI_ENABLE_DARKWEB_COLLECTOR", raising=False)

    result = run_darkweb_collector()
    captured = capsys.readouterr()

    assert result == 0
    assert "skipped" in captured.out.lower()


def test_darkweb_collector_enabled_is_explicit_noop(monkeypatch, capsys):
    monkeypatch.setenv("PI_ENABLE_DARKWEB_COLLECTOR", "1")

    result = run_darkweb_collector()
    captured = capsys.readouterr()

    assert result == 0
    assert "not implemented" in captured.out.lower()
