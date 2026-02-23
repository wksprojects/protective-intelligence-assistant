# Incident Thread Case Pack

Generated: 2026-02-23 18:14:00 UTC

## Ingestion Summary
- Telegram prototype alerts ingested this run: **3**
- Chans prototype alerts ingested this run: **3**

## Thread Snapshot
- `thread_id`: `soi-5-2`
- `label`: **Actor anon_b39c**
- alerts: **2**
- sources: **2** (Chans / Fringe Boards (Prototype), Telegram Public Channels (Prototype))
- time window: **2026-02-22 09:10:00 → 2026-02-22 11:40:00**
- max ORS: **53.0**
- max TAS: **0.0**
- recommended escalation tier: **ROUTINE**

## Correlation Evidence
- actor handles: anon_b39c, city_grievance_watch
- shared entities: none
- matched terms: death threat
- linked POIs: none

- Actor-handle evidence present; validate continuity during analyst review.
- Multi-source corroboration across independent feeds.
- Recurring threat vocabulary over a constrained time window.

## Timeline
| Timestamp | Source | Type | ORS | TAS | Matched Term | Title |
|---|---|---|---:|---:|---|---|
| 2026-02-22 09:10:00 | Telegram Public Channels (Prototype) | telegram | 53.0 | 0.0 | death threat | Repeated grievance escalation toward executive |
| 2026-02-22 11:40:00 | Chans / Fringe Boards (Prototype) | chans | 38.2 | 0.0 | death threat | /b/ post with explicit threat language |

## Analyst Action
Maintain monitoring queue and reassess at next collection cycle.

## Reproduce
```bash
make init
PI_ENABLE_TELEGRAM_COLLECTOR=1 PI_ENABLE_CHANS_COLLECTOR=1 python run.py scrape
curl "http://localhost:8000/analytics/soi-threads?days=14&window_hours=72&min_cluster_size=2"
```
