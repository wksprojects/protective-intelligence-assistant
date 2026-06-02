# Reviewable Output Summary

Generated: 2026-06-01  
Purpose: static portfolio artifacts for analyst-output review

## What These Outputs Show

These outputs demonstrate how the project turns normalized alerts and public context into reviewable analyst artifacts. They are intentionally conservative: each item includes scope, source type, confidence, recommended review action, and limitations.

## Included Artifacts

| Artifact | Purpose |
|---|---|
| `outputs/review_queue.csv` | Compact queue of items an analyst could review, including source type, confidence, and next action. |
| `outputs/entity_or_event_rollup.csv` | Entity/event context rollup for a fictional public-data travel review. |
| `docs/public_companion_casepack.md` | Public-source-only companion casepack showing workflow structure without real investigations. |
| `docs/methodology.md` | Explanation of collection, normalization, scoring, correlation, and review methodology. |
| `docs/limitations.md` | Public framing, data limits, analytical limits, and operational caveats. |

## Review Posture

- Synthetic and public-source examples only.
- No real investigations or private protectee data.
- Scores and reason codes are triage aids, not findings.
- Casepacks are designed to support review, documentation, and reproducibility.
