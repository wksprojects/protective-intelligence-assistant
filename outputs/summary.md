# Reviewable Output Summary

Generated: 2026-06-02
Purpose: static portfolio artifacts for analyst-output review

## What These Outputs Show

These outputs demonstrate how the project turns normalized alerts and public context into reviewable analyst artifacts. They are intentionally conservative: each item includes scope, source type, confidence, recommended review action, and limitations.

## Included Artifacts

| Artifact | Purpose |
|---|---|
| `outputs/review_queue.csv` | Compact queue of items an analyst could review, including source type, confidence, and next action. |
| `outputs/entity_or_event_rollup.csv` | Entity/event context rollup for a fictional public-data travel review. |
| `outputs/public_travel_advisory_source_rows.csv` | 240 official public RSS rows from State Department and CDC feeds. |
| `outputs/public_travel_advisory_review_queue.csv` | 149 critical/high/medium travel-risk review queue rows derived from official public feeds. |
| `outputs/public_travel_advisory_rollup.csv` | Briefing rollup by source, advisory level, and priority. |
| `docs/public_travel_advisory_case_study.md` | Real public-data companion case study for travel-risk review. |
| `docs/public_companion_casepack.md` | Public-source-only companion casepack showing workflow structure without real investigations. |
| `docs/methodology.md` | Explanation of collection, normalization, scoring, correlation, and review methodology. |
| `docs/limitations.md` | Public framing, data limits, analytical limits, and operational caveats. |

## Review Posture

- Synthetic fixtures plus official public RSS companion data.
- No real investigations or private protectee data.
- Scores and reason codes are triage aids, not findings.
- Casepacks are designed to support review, documentation, and reproducibility.
