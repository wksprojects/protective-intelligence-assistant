"""Top-level collector orchestration facade."""

from scraper import run_all_scrapers


def run_all_collectors():
    """Run the full collector pipeline."""
    return run_all_scrapers()
