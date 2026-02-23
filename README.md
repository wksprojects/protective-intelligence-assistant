# Protective Intelligence Assistant

Automated behavioral threat assessment via multi-source correlation for protective intelligence workflows.

The platform ingests open-source signals, links related activity into incident threads, scores risk with explainable logic, and produces analyst-ready outputs (daily reports, travel briefs, SITREPs).

## What This Project Demonstrates

- Protective intelligence workflow design, not just alert scraping.
- Quantitative triage with explainable scoring (ORS, TAS, uncertainty intervals).
- Correlation logic that reduces analyst noise by clustering related signals into Subject of Interest (SOI) threads.
- Operational reliability patterns (source health, fail streaks, auto-disable of dead feeds).
- Production-minded API, auditability, and environment-gated collectors.

## Current Status

Implemented now:

- Multi-source ingestion: RSS, Reddit RSS, Pastebin, optional ACLED.
- Environment-gated prototype collectors: Telegram and chans (fixture-first).
- Dark-web collector scaffold wired into pipeline, disabled by default.
- SOI thread correlation endpoint.
- Targeted source preset preview endpoint for event/location watchlist expansion.
- Signal-quality analytics endpoint (precision-oriented TP/FP tracking by source/category).
- Source health telemetry fields and auto-disable controls.

## Screenshots

| Situation Overview | Alert Triage |
|---|---|
| ![Overview](docs/screenshots/overview.png) | ![Triage](docs/screenshots/triage.png) |

| Protectee Risk | Intelligence Analysis |
|---|---|
| ![Risk](docs/screenshots/protectee_risk.png) | ![Intelligence Analysis](docs/screenshots/intelligence_analysis.png) |

## Architecture

### Implemented Data Flow

```mermaid
flowchart LR
    subgraph Sources
        RSS[RSS feeds]
        Reddit[Reddit RSS]
        Paste[Pastebin Archive]
        ACLED[ACLED (optional)]
        TG[Telegram prototype]
        Chans[Chans prototype]
        DW[Dark-web scaffold]
    end

    subgraph Ingestion
        Collect[Collectors]
        Match[Keyword match + dedup]
        Extract[Entity extraction + POI/location enrichment]
    end

    subgraph Intelligence Engine
        Corr[SOI Correlation Threads]
        ORS[Operational Risk Score]
        TAS[Threat Assessment Score]
        MC[Monte Carlo Uncertainty]
    end

    subgraph Analyst Outputs
        Alerts[Prioritized Alerts]
        Threads[Incident Threads]
        Daily[Daily Intel Report]
        Travel[Travel Brief]
        SITREP[SITREP]
    end

    DB[(SQLite)]
    API[FastAPI]
    UI[Streamlit]

    RSS --> Collect
    Reddit --> Collect
    Paste --> Collect
    ACLED --> Collect
    TG --> Collect
    Chans --> Collect
    DW --> Collect

    Collect --> Match --> Extract --> DB
    DB --> Corr
    DB --> ORS
    DB --> TAS
    ORS --> MC
    TAS --> MC

    Corr --> Threads
    MC --> Alerts
    DB --> Daily
    DB --> Travel
    DB --> SITREP

    DB --> API --> UI
```

### Target v2 Architecture (Roadmap)

```mermaid
flowchart LR
    A[Adversarial + Public Sources] --> B[Collection Layer]
    B --> C[Normalized Artifact Store]
    B --> D[Vector Index (planned)]
    C --> E[Correlation Engine]
    D --> E
    E --> F[Incident Threads + Confidence]
    F --> G[Analyst Alert Queue + Reporting]
```

Note: vector index/semantic matching is planned, not in the current production path.

## Quant Logic

### 1) Alert Scoring

- ORS combines keyword weight, source credibility, frequency anomaly, recency, and contextual factors.
- TAS applies behavioral threat indicators (fixation, leakage, pathway, targeting specificity, etc.).
- Uncertainty intervals are computed via Monte Carlo for defensible prioritization.

### 2) Entity Resolution and Correlation (Current)

SOI threads are currently linked by rule-based evidence plus temporal proximity:

- shared POI hits
- shared entities (`actor_handle`, `domain`, `ipv4`, `url`)
- shared matched threat term
- configurable time window (default 72h; term-level link window 24h)

Output: clustered incident timelines instead of isolated alerts.

### 3) Planned Correlation Upgrade

Planned next step is a weighted confidence model with reason codes, adding:

- linguistic similarity/fingerprinting
- stronger cross-source actor linking
- explicit thread confidence score

## Quick Start

```bash
pip install -r requirements.txt
make clean && make init && make scrape
```

Start services:

```bash
# terminal 1
make api

# terminal 2
make dashboard
```

Optional demo artifacts:

```bash
make demo
```

Generate an analyst-ready incident thread case pack:

```bash
make casepack
```

## Environment-Gated Collection Modes

Prototype and high-risk collectors are disabled by default.

- `PI_ENABLE_TELEGRAM_COLLECTOR=1` enables Telegram prototype collector.
- `PI_ENABLE_CHANS_COLLECTOR=1` enables chans prototype collector.
- `PI_ENABLE_DARKWEB_COLLECTOR=1` enables dark-web scaffold path (still non-operational by design).

Source reliability controls:

- `PI_SOURCE_AUTO_DISABLE=1` enables automatic disabling after repeated failures.
- `PI_SOURCE_FAIL_DISABLE_THRESHOLD=5` sets consecutive-failure threshold.

## Key Endpoints

### Correlation and Intelligence

- `GET /analytics/soi-threads`
- `GET /analytics/source-presets`
- `GET /analytics/signal-quality`
- `GET /analytics/source-health`

### Collection Triggers

- `POST /scrape/telegram`
- `POST /scrape/chans`
- `POST /scrape/social-media`

### Core Analyst Workflow

- `GET /alerts`
- `GET /alerts/{id}/score?uncertainty=1`
- `POST /alerts/{id}/disposition`
- `GET /pois/{id}/assessment`
- `POST /briefs/travel`
- `POST /sitreps/generate/poi/{id}`

## Example: Pull Incident Threads

```bash
curl "http://localhost:8000/analytics/soi-threads?days=14&window_hours=72&min_cluster_size=2"
```

Generated case-pack artifact:

- `docs/incident_thread_casepack.md`

## Security and Data Handling Disclosure

### API Key Handling

- API key auth uses `PI_API_KEY` (or legacy `OSINT_API_KEY`).
- If key enforcement is enabled (`PI_REQUIRE_API_KEY=1`), endpoints with auth dependency require `X-API-Key`.
- Local dev can run without auth when keys are unset.

### Request/Audit Controls

- Request IDs are assigned per request (`X-Request-ID` support).
- Mutation requests are written to `audit_log` with method/path/status/duration and client metadata.
- Security headers are added (`X-Content-Type-Options`, `X-Frame-Options`).

### PII/Protectee Redaction

- Generated intel products can redact active POI names/aliases via `REDACT_PERSON_ENTITIES=1`.
- Redaction is applied to reports/briefs/SITREPs before output.

### Retention

- Raw alert content retention is bounded by `RAW_CONTENT_RETENTION_DAYS` (default 30).
- Purge command nulls old raw content while preserving structured analytical metadata.

## Data Science Validation

Reproducible evaluation memo:

```bash
make evaluate
```

Output:

- `docs/evaluation_memo.md`

Current repo also includes:

- backtesting workflow
- ML comparison endpoint (`GET /analytics/ml-comparison`)
- precision/recall analytics endpoint (`GET /analytics/evaluation`)

## Source Health Telemetry (Current vs Next)

Current persisted fields include:

- `fail_streak`
- `last_status`
- `last_error`
- `last_success_at`
- `last_failure_at`
- `disabled_reason`

Planned telemetry additions:

- per-collector latency
- last collection count
- uptime rollups and SLO reporting

## Deployment

Containerized options are already included:

- `Dockerfile`
- `docker-compose.yml`

Run locally:

```bash
docker compose up --build
```

## Testing

```bash
python -m pytest tests/ -v
```

Current suite status: 75 passing tests.

## Legal and Operational Note

This repository is an analyst-assistance platform. Any operational collection on adversarial or platform-restricted sources must follow organizational legal review, platform terms, and applicable privacy/civil-liberties policies before activation.
