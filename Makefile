.PHONY: demo init sync scrape api dashboard test smoke purge-demo evaluate benchmark correlation-eval insider-eval supplychain-eval supply-chain-eval supply_chain_eval heartbeat casepack screenshots clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

init: ## Initialize database and seed EP config from watchlist.yaml
	python run.py init

sync: ## Sync watchlist config into existing database
	python run.py sync

demo: init ## Full demo: init → load fixtures → generate artifacts → print URLs
	python run.py demo
	python scripts/generate_demo_proof_artifacts.py
	@echo ""
	@echo "══════════════════════════════════════════════════════════"
	@echo "  Demo artifacts generated:"
	@echo "    docs/sample_casepack.md"
	@echo "    out/sitrep.md"
	@echo "    docs/demo_daily_report.md"
	@echo "    docs/demo_travel_brief.md"
	@echo ""
	@echo "  Start the stack:"
	@echo "    Terminal 1:  make api        → http://localhost:8000"
	@echo "    Terminal 2:  make dashboard  → http://localhost:8501"
	@echo "══════════════════════════════════════════════════════════"

scrape: init ## Run all scrapers (+ optional darkweb, telegram, chans prototypes)
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

benchmark: ## Generate compact benchmark metrics table
	python scripts/generate_benchmark_table.py

correlation-eval: ## Evaluate correlation engine precision/recall on hand-labeled cases
	python scripts/generate_correlation_eval.py

insider-eval: ## Evaluate insider-risk scorer precision/recall on labeled fixtures
	python scripts/generate_insider_eval.py

supplychain-eval: ## Evaluate supply-chain risk scaffold precision/recall on labeled fixtures
	python scripts/generate_supply_chain_eval.py

supply-chain-eval: supplychain-eval ## Alias: hyphenated supply-chain eval target

supply_chain_eval: supplychain-eval ## Alias: underscored supply-chain eval target

heartbeat: ## Generate source health heartbeat snapshot + append-only log
	python scripts/generate_source_health_heartbeat.py

casepack: ## Generate incident thread analyst case pack
	python scripts/generate_incident_thread_casepack.py

screenshots: ## Generate README screenshot artifacts (insider/supply-chain/convergence)
	python scripts/generate_readme_screenshots.py

clean: ## Remove database and cached artifacts
	rm -f database/protective_intel.db
	rm -f database/osint_monitor.db
	rm -f docs/evaluation_memo.md
	rm -f docs/benchmark_table.md
	rm -f docs/correlation_eval.md
	rm -f docs/insider_eval.md
	rm -f docs/supply_chain_eval.md
	rm -f docs/source_health_heartbeat.md
	rm -f docs/source_health_heartbeat.jsonl
	rm -f docs/incident_thread_casepack.md
	rm -f docs/sample_casepack.md
	rm -f docs/demo_daily_report.md docs/demo_travel_brief.md
	rm -f docs/protectee_view.svg docs/map_view.svg
	rm -f out/sitrep.md
	@echo "Cleaned database and demo artifacts."
