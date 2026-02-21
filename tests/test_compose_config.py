from pathlib import Path

import yaml


def test_compose_uses_valid_scraper_entrypoint_and_dashboard_api_env():
    compose_path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
    with compose_path.open("r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    scraper_command = compose["services"]["scraper"]["command"]
    assert scraper_command == "python run.py scrape"

    dashboard_env = compose["services"]["dashboard"].get("environment", [])
    assert "PI_API_URL=http://api:8000" in dashboard_env
