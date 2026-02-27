import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from api.main import _scrape_limiter, app
from database import init_db as db_init


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = Path(tmp_path) / "osint_test.db"
    monkeypatch.setattr(db_init, "DB_PATH", str(db_path))

    db_init.init_db()
    db_init.migrate_schema()
    db_init.seed_default_sources()
    db_init.seed_default_keywords()
    db_init.seed_default_pois()
    db_init.seed_default_protected_locations()
    db_init.seed_default_events()
    db_init.seed_threat_actors()

    # Reset rate limiter between tests so scrape endpoints are not blocked
    _scrape_limiter.reset()

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
