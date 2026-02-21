.PHONY: demo init sync scrape api dashboard test smoke purge-demo evaluate clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

init: ## Initialize database and seed EP config from watchlist.yaml
	python run.py init

sync: ## Sync watchlist config into existing database
	python run.py sync

demo: init ## Full demo: init → load fixtures → generate artifacts → print URLs
	python run.py demo
	@echo ""
	@echo "══════════════════════════════════════════════════════════"
	@echo "  Demo artifacts generated:"
	@echo "    docs/demo_daily_report.md"
	@echo "    docs/demo_travel_brief.md"
	@echo "    docs/protectee_view.svg"
	@echo "    docs/map_view.svg"
	@echo ""
	@echo "  Start the stack:"
	@echo "    Terminal 1:  make api        → http://localhost:8000"
	@echo "    Terminal 2:  make dashboard  → http://localhost:8501"
	@echo "══════════════════════════════════════════════════════════"

scrape: init ## Run all scrapers (RSS/Reddit/Pastebin/ACLED)
	python run.py scrape

api: ## Start FastAPI server on :8000
	python run.py api

dashboard: ## Start Streamlit dashboard on :8501
	python run.py dashboard

test: ## Run full pytest suite
	python -m pytest tests/ -v

smoke: ## Quick smoke test (init → demo → compile check)
	./scripts/smoke_test.sh

purge-demo: ## Remove demo-seeded content from the database
	python run.py purge-demo

evaluate: ## Generate reproducible quantitative evaluation memo
	python scripts/generate_evaluation_memo.py

clean: ## Remove database and cached artifacts
	rm -f database/protective_intel.db
	rm -f database/osint_monitor.db
	rm -f docs/evaluation_memo.md
	rm -f docs/demo_daily_report.md docs/demo_travel_brief.md
	rm -f docs/protectee_view.svg docs/map_view.svg
	@echo "Cleaned database and demo artifacts."
