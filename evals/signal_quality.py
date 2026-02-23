"""Signal quality evaluation facade."""

from analytics.signal_quality import compute_signal_quality


def compute_signal_quality_view(window_days=30, include_demo=False):
    return compute_signal_quality(window_days=window_days, include_demo=include_demo)
