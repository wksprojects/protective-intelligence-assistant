"""Correlation processing facade."""

from analytics.soi_threads import build_soi_threads


def build_incident_threads(
    days=14,
    window_hours=72,
    min_cluster_size=2,
    limit=50,
    include_demo=False,
):
    return build_soi_threads(
        days=days,
        window_hours=window_hours,
        min_cluster_size=min_cluster_size,
        limit=limit,
        include_demo=include_demo,
    )
