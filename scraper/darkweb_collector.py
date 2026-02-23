"""Dark-web collector scaffold.

This module intentionally ships in disabled mode. It provides a stable
integration point in the scraper pipeline while policy/legal review and source
validation are completed.
"""

import os


def _enabled():
    return os.getenv("PI_ENABLE_DARKWEB_COLLECTOR", "0").lower() in {"1", "true", "yes"}


def run_darkweb_collector(frequency_snapshot=None):
    """Placeholder collector for future dark-web integrations.

    Returns:
        int: Number of new alerts ingested (always 0 in scaffold mode).
    """
    # Keep function signature aligned with other collectors.
    _ = frequency_snapshot

    if not _enabled():
        print("Dark-web collector skipped (PI_ENABLE_DARKWEB_COLLECTOR not set).")
        return 0

    print(
        "Dark-web collector is enabled but not implemented. "
        "Complete legal/ToS review and connector hardening before activation."
    )
    return 0
