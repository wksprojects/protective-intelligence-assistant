"""Telegram collector facade."""

from scraper.telegram_collector import run_telegram_collector


def collect_telegram(frequency_snapshot=None):
    return run_telegram_collector(frequency_snapshot=frequency_snapshot)
