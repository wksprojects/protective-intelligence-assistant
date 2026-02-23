# Incident Thread Case Pack

Generated: 2026-02-23 18:04:36 UTC

## Ingestion Summary
- Telegram prototype alerts ingested this run: **0**
- Chans prototype alerts ingested this run: **0**

## Thread Snapshot
- `thread_id`: `soi-365-2`
- `label`: **Actor @crossplatform_subject**
- alerts: **2**
- sources: **2** (Chans / Fringe Boards (Prototype), Telegram Public Channels (Prototype))
- time window: **2026-02-23 18:04:36 → 2026-02-23 18:04:36**
- max ORS: **91.0**
- max TAS: **48.0**
- recommended escalation tier: **CRITICAL**

## Correlation Evidence
- actor handles: @crossplatform_subject
- shared entities: none
- matched terms: death threat
- linked POIs: none

- Actor-handle evidence present; validate continuity during analyst review.
- Multi-source corroboration across independent feeds.
- Recurring threat vocabulary over a constrained time window.

## Timeline
| Timestamp | Source | Type | ORS | TAS | Matched Term | Title |
|---|---|---|---:|---:|---|---|
| 2026-02-23 18:04:36 | Telegram Public Channels (Prototype) | telegram | 91.0 | 48.0 | death threat | Cross-platform threat escalation (Telegram) |
| 2026-02-23 18:04:36 | Chans / Fringe Boards (Prototype) | chans | 88.0 | 44.0 | death threat | Cross-platform threat escalation (chans) |

## Analyst Action
Immediate escalation to protective detail lead and intelligence manager (target: 30 minutes).

## Reproduce
```bash
make init
PI_ENABLE_TELEGRAM_COLLECTOR=1 PI_ENABLE_CHANS_COLLECTOR=1 python run.py scrape
curl "http://localhost:8000/analytics/soi-threads?days=14&window_hours=72&min_cluster_size=2"
```
