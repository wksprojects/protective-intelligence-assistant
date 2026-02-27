"""
Shared utility functions for the analytics layer.

Centralizes timestamp parsing and recency computation to avoid
divergent copies across modules.
"""

from datetime import datetime, timezone


def utcnow():
    """Return the current UTC time as a naive datetime (no tzinfo).

    Replaces the deprecated ``datetime.utcnow()`` while keeping the rest
    of the codebase free from timezone-aware/naive comparison headaches.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_timestamp(value):
    """Parse common timestamp formats into a naive UTC datetime.

    Supported inputs:
      - ``None`` / empty string -> ``None``
      - ``datetime`` instance (returned as-is after UTC conversion)
      - ISO-8601 strings  (``2024-01-15T12:30:00Z``, ``2024-01-15T12:30:00+05:00``)
      - ``YYYY-MM-DD HH:MM:SS``
      - ``YYYY-MM-DD``
    """
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    dt = None
            if dt is None:
                return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def compute_recency_factor(published_at=None, created_at=None):
    """Compute a recency factor and the underlying recency_hours.

    Returns:
        ``(recency_factor, recency_hours)`` tuple.
        ``recency_factor`` decays linearly from 1.0 (now) to 0.1 (168 h).
        Future-dated events are clamped to 0 hours (treated as "just now")
        to prevent score inflation from feeds with future timestamps.
    """
    event_dt = parse_timestamp(published_at) or parse_timestamp(created_at) or utcnow()
    recency_hours = max(0.0, (utcnow() - event_dt).total_seconds() / 3600.0)
    return max(0.1, 1.0 - (recency_hours / 168.0)), recency_hours
