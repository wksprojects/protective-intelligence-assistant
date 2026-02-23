"""Chans collector facade."""

from scraper.chans_collector import run_chans_collector


def collect_chans(frequency_snapshot=None):
    return run_chans_collector(frequency_snapshot=frequency_snapshot)
