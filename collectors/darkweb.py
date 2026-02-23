"""Dark-web collector facade."""

from scraper.darkweb_collector import run_darkweb_collector


def collect_darkweb(frequency_snapshot=None):
    return run_darkweb_collector(frequency_snapshot=frequency_snapshot)
