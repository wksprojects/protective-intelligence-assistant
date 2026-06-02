# Methodology

This project models an analyst-assistance workflow for protective intelligence review. It is designed for public, reproducible demonstration using synthetic fixtures and openly available public context. It is not presented as a live monitoring service, investigative finding, or operational security product.

## Workflow

1. **Requirements and scope**
   - Define the protectee, facility, travel window, or third-party context under review.
   - Record collection constraints and data assumptions before scoring.
   - Separate public-source context from private, sensitive, or restricted telemetry.

2. **Collection**
   - Fixture collectors provide synthetic OSINT, insider-risk, and vendor-risk examples.
   - Public companion artifacts use official public sources only.
   - Restricted-platform prototypes are environment-gated and disabled by default.

3. **Normalization and extraction**
   - Alerts are normalized into common fields: source, timestamp, title, content, matched term, severity, score, and entities.
   - Entity extraction carries structured pivots such as POIs, locations, domains, IPs, URLs, user IDs, device IDs, and vendor IDs.
   - Deduplication and source-health checks reduce repeated or stale signals.

4. **Correlation**
   - Subject-of-interest threads link alerts through shared entities, POI hits, matched-term temporal overlap, source fingerprints, cross-source corroboration, and temporal proximity.
   - Pair evidence records why two alerts were linked and the confidence contribution for that edge.
   - Threads are review queues, not adjudicated findings.

5. **Scoring**
   - ORS estimates operational risk from keyword weight, source credibility, frequency anomaly, recency, and contextual features.
   - TAS adapts behavioral threat-assessment indicators for protectee triage.
   - IRS and vendor-risk scores are fixture-only demonstrations of insider and third-party risk factors.
   - Uncertainty intervals are used to avoid over-reading exact point scores.

6. **Review and output**
   - Outputs prioritize explainability: reason codes, confidence, assumptions, evidence links, and recommended next review steps.
   - Casepacks are structured for analyst review: scope, timeline, entities, risk factors, confidence, recommendations, and limitations.
   - Dispositions and audit records support traceability when alerts are reviewed.

## Public-Source Companion Method

The public-data companion casepack uses official public sources as context inputs. It does not identify a real protectee, assert a specific threat, or infer non-public intent. Its purpose is to demonstrate how the tool would structure a review when public travel advisories, threat-level context, and event-planning guidance are available.

Public-source context is treated as baseline context unless it includes a specific, time-bound alert. Baseline context can raise planning priority, but it does not create a finding by itself.

## Reproducibility

Core demo artifacts can be regenerated with:

```bash
make demo
make casepack
make correlation-eval
make insider-eval
make supplychain-eval
```

Committed review artifacts are intentionally static so a portfolio reviewer can inspect the output shape without running the stack.
