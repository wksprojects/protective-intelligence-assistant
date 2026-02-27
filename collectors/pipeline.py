"""Top-level collector orchestration facade."""

from collectors.insider_telemetry import collect_insider_telemetry
from collectors.supply_chain import collect_supply_chain
from scraper import run_all_scrapers


def run_all_collectors():
    """Run the full collector pipeline."""
    total = run_all_scrapers()
    total += collect_insider_telemetry()
    total += collect_supply_chain()
    return total
