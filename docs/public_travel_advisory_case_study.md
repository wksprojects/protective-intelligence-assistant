# Public Travel Advisory Case Study

Generated: 2026-06-02 13:44 UTC
Data class: official public RSS feeds
Disposition: review queue inputs, not threat findings

## Dataset

This companion case study uses official public travel-risk feeds to demonstrate how the Protective Intelligence Assistant can turn public context into reviewable outputs for travel and protective-intelligence planning.

| Source | Rows | Feed |
|---|---:|---|
| U.S. Department of State Travel Advisories | 215 | https://travel.state.gov/_res/rss/TAsTWs.xml |
| CDC Travel Health Notices | 25 | https://wwwnc.cdc.gov/travel/rss/notices.xml |
| Total | 240 | two official public RSS feeds |

## Output Metrics

| Metric | Count |
|---|---:|
| Critical review items | 25 |
| High review items | 60 |
| Medium review items | 64 |
| Level 4 / equivalent notices | 24 |
| Level 3 / equivalent notices | 29 |
| Level 2 / equivalent notices | 93 |

## Workflow

1. Fetch official public RSS rows from State Department and CDC feeds.
2. Normalize each item into source, destination or notice, published date, advisory level, and URL.
3. Score rows using advisory level and keyword context such as terrorism, unrest, crime, kidnapping, outbreak, and disease indicators.
4. Route critical, high, and medium rows into an analyst review queue.
5. Produce rollups by source, advisory level, and priority for quick briefing.

## Representative Review Queue

| Queue ID | Priority | Source | Destination or Notice | Level | Score | Recommended Review |
|---|---|---|---|---:|---:|---|
| PTA-001 | critical | U.S. Department of State Travel Advisories | Afghanistan | 4 | 100 | Require analyst review before travel planning or itinerary approval. |
| PTA-002 | high | U.S. Department of State Travel Advisories | Azerbaijan | 3 | 100 | Validate itinerary relevance and identify exposure controls. |
| PTA-003 | high | U.S. Department of State Travel Advisories | Bangladesh | 3 | 100 | Validate itinerary relevance and identify exposure controls. |
| PTA-004 | high | U.S. Department of State Travel Advisories | Benin | 2 | 100 | Validate itinerary relevance and identify exposure controls. |
| PTA-005 | critical | U.S. Department of State Travel Advisories | Burkina Faso | 4 | 100 | Require analyst review before travel planning or itinerary approval. |
| PTA-006 | critical | U.S. Department of State Travel Advisories | Burma | 4 | 100 | Require analyst review before travel planning or itinerary approval. |
| PTA-007 | critical | U.S. Department of State Travel Advisories | Burma | 4 | 100 | Require analyst review before travel planning or itinerary approval. |
| PTA-008 | high | U.S. Department of State Travel Advisories | Cameroon | 2 | 100 | Validate itinerary relevance and identify exposure controls. |
| PTA-009 | critical | U.S. Department of State Travel Advisories | Central African Republic | 4 | 100 | Require analyst review before travel planning or itinerary approval. |
| PTA-010 | critical | U.S. Department of State Travel Advisories | Chad | 4 | 100 | Require analyst review before travel planning or itinerary approval. |

Full outputs:

- `outputs/public_travel_advisory_source_rows.csv`
- `outputs/public_travel_advisory_review_queue.csv`
- `outputs/public_travel_advisory_rollup.csv`

## Scope and Limitations

- These rows are official public advisories and health notices, not private intelligence or law-enforcement reporting.
- Scores are triage aids for review priority; they do not establish a specific threat to a person, organization, route, or event.
- Advisory relevance still depends on itinerary, traveler profile, timing, local movement, venue exposure, and operational context.
- The feed snapshot can change as agencies update or remove advisories.
