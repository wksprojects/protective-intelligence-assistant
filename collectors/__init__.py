"""Collector-facing package boundary.

This package provides stable entry points for collection workflows while
preserving compatibility with existing scraper modules.
"""

from collectors.chans import collect_chans
from collectors.darkweb import collect_darkweb
from collectors.insider_telemetry import collect_insider_telemetry
from collectors.pipeline import run_all_collectors
from collectors.supply_chain import collect_supply_chain
from collectors.telegram import collect_telegram

__all__ = [
    "run_all_collectors",
    "collect_telegram",
    "collect_chans",
    "collect_darkweb",
    "collect_insider_telemetry",
    "collect_supply_chain",
]
