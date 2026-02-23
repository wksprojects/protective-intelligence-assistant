"""Observer-style health instrumentation for collectors."""

from __future__ import annotations

import time
from contextlib import contextmanager


class CollectorHealthObserver:
    """Observer that records collector success/failure telemetry."""

    def __init__(self, conn, collector_name):
        self.conn = conn
        self.collector_name = str(collector_name or "collector").strip() or "collector"

    @contextmanager
    def observe(self, source_id, collection_count=None):
        """Observe one collector execution window for a source."""
        started_at = time.perf_counter()
        try:
            yield
        except Exception as exc:
            if source_id is not None:
                from scraper.source_health import mark_source_failure

                mark_source_failure(
                    self.conn,
                    source_id,
                    f"{self.collector_name} collector error: {exc!r}",
                )
            raise
        else:
            if source_id is not None:
                from scraper.source_health import mark_source_success

                if callable(collection_count):
                    count_value = collection_count()
                else:
                    count_value = collection_count
                elapsed_ms = (time.perf_counter() - started_at) * 1000.0
                mark_source_success(
                    self.conn,
                    source_id,
                    collection_count=count_value,
                    latency_ms=elapsed_ms,
                )
