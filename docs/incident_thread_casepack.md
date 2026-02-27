# Incident Thread Case Pack

Generated: 2026-02-27 21:07:10 UTC

## Scope and Sanitization
- Synthetic fixture data only (no production identities, no classified/regulated datasets).
- Purpose: demonstrate cross-domain correlation and explainable prioritization.

## Fixture Ingestion Summary
- Telegram prototype alerts ingested: **3**
- Chans prototype alerts ingested: **3**
- Insider telemetry alerts ingested: **10**
- Supply-chain alerts ingested: **6**
- External bridge alerts ingested: **1**

## Thread Snapshot
- `thread_id`: `soi-e5551e4f98fe`
- `label`: **Term death threat**
- alerts: **10**
- sources: **3** (External OSINT Bridge (Fixture), Insider Telemetry (Fixture UEBA), Supply Chain Risk (Fixture Scaffold))
- source types: **insider, rss, supply_chain**
- time window: **2026-02-25 23:58:00 → 2026-02-27 21:07:10**
- max ORS: **99.4**
- max TAS: **0.0**
- thread confidence: **0.89**
- recommended escalation tier: **CRITICAL**

## Correlation Evidence
- reason codes: cross_source, linguistic_overlap_high, linguistic_overlap_medium, matched_term_temporal, shared_entity, shared_source_fingerprint, shared_user_id, shared_vendor_id, tight_temporal
- shared entities: device_id:lptp-553, device_id:lptp-812, device_id:lptp-991, domain:aster-cloud.example, domain:bastion-sync.example, domain:blue-meridian-travel.example, domain:harborview-facilities.example, domain:northbridge-id.example, domain:praxis-payroll.example, domain:summit-badge.example, domain:sync-archive.example, ipv4:203.0.113.142, ipv4:203.0.113.76, user_id:emp-5074, user_id:emp-7415, user_id:emp-8891, vendor_id:sc-001, vendor_id:sc-002, vendor_id:sc-003, vendor_id:sc-004
- matched terms: death threat, insider telemetry anomaly, third party vendor risk

## Provenance Keys
- user_id values in thread: emp-5074, emp-7415, emp-8891
- device_id values in thread: lptp-553, lptp-812, lptp-991
- vendor_id values in thread: sc-001, sc-002, sc-003, sc-004, sc-005, sc-006
- domain values in thread: aster-cloud.example, bastion-sync.example, blue-meridian-travel.example, harborview-facilities.example, northbridge-id.example, praxis-payroll.example, summit-badge.example, sync-archive.example

## Insider Risk Context
| Subject ID | Subject Name | IRS | Tier |
|---|---|---|---|
| EMP-7415 | C. Webb | 73.5 | HIGH |
| EMP-8891 | J. Ortega | 65.2 | ELEVATED |
| EMP-5074 | L. Brooks | 62.3 | ELEVATED |

## Supply-Chain Context
| Vendor ID | Vendor Name | Domain | Risk Score | Tier |
|---|---|---|---|---|
| sc-001 | Northbridge Identity Operations | northbridge-id.example | 99.4 | HIGH |
| sc-004 | Aster Cloud Analytics | aster-cloud.example | 83.3 | HIGH |
| sc-005 | Summit Badge Integrations | summit-badge.example | 70.8 | ELEVATED |
| sc-003 | Blue Meridian Travel Partners | blue-meridian-travel.example | 47.5 | GUARDED |
| sc-006 | Praxis Payroll Outsourcing | praxis-payroll.example | 40.5 | GUARDED |
| sc-002 | Harborview Facilities Services | harborview-facilities.example | 19.3 | LOW |

## Timeline
| Timestamp | Source | Type | ORS | TAS | Matched Term | Title |
|---|---|---|---:|---:|---|---|
| 2026-02-25 23:58:00 | Insider Telemetry (Fixture UEBA) | insider | 60.2 | 0.0 | insider telemetry anomaly | Attempted privilege escalation and HR stressor convergence |
| 2026-02-26 00:47:00 | Insider Telemetry (Fixture UEBA) | insider | 57.3 | 0.0 | insider telemetry anomaly | Late-night recon on restricted engineering docs |
| 2026-02-26 03:36:00 | Insider Telemetry (Fixture UEBA) | insider | 68.5 | 0.0 | insider telemetry anomaly | Sustained high-volume extraction with external contact expansion |
| 2026-02-27 21:07:10 | Supply Chain Risk (Fixture Scaffold) | supply_chain | 99.4 | 0.0 | third party vendor risk | Vendor risk assessment: Northbridge Identity Operations |
| 2026-02-27 21:07:10 | Supply Chain Risk (Fixture Scaffold) | supply_chain | 19.3 | 0.0 | third party vendor risk | Vendor risk assessment: Harborview Facilities Services |
| 2026-02-27 21:07:10 | Supply Chain Risk (Fixture Scaffold) | supply_chain | 47.5 | 0.0 | third party vendor risk | Vendor risk assessment: Blue Meridian Travel Partners |
| 2026-02-27 21:07:10 | Supply Chain Risk (Fixture Scaffold) | supply_chain | 83.3 | 0.0 | third party vendor risk | Vendor risk assessment: Aster Cloud Analytics |
| 2026-02-27 21:07:10 | Supply Chain Risk (Fixture Scaffold) | supply_chain | 70.8 | 0.0 | third party vendor risk | Vendor risk assessment: Summit Badge Integrations |
| 2026-02-27 21:07:10 | Supply Chain Risk (Fixture Scaffold) | supply_chain | 40.5 | 0.0 | third party vendor risk | Vendor risk assessment: Praxis Payroll Outsourcing |
| 2026-02-27 21:07:10 | External OSINT Bridge (Fixture) | rss | 78.0 | 0.0 | death threat | External forum signal references insider-linked identifier and vendor |

## Pairwise Link Provenance
| Left Alert | Right Alert | Score | Reason Codes |
|---|---|---|---|
| 20 | 23 | 1.00 | cross_source, shared_entity, shared_vendor_id, tight_temporal |
| 17 | 18 | 0.75 | linguistic_overlap_high, matched_term_temporal, shared_source_fingerprint, tight_temporal |
| 17 | 19 | 0.75 | linguistic_overlap_high, matched_term_temporal, shared_source_fingerprint, tight_temporal |
| 17 | 20 | 0.75 | linguistic_overlap_high, matched_term_temporal, shared_source_fingerprint, tight_temporal |
| 17 | 21 | 0.75 | linguistic_overlap_high, matched_term_temporal, shared_source_fingerprint, tight_temporal |
| 17 | 22 | 0.75 | linguistic_overlap_high, matched_term_temporal, shared_source_fingerprint, tight_temporal |
| 18 | 19 | 0.75 | linguistic_overlap_high, matched_term_temporal, shared_source_fingerprint, tight_temporal |
| 18 | 20 | 0.75 | linguistic_overlap_high, matched_term_temporal, shared_source_fingerprint, tight_temporal |
| 18 | 21 | 0.75 | linguistic_overlap_high, matched_term_temporal, shared_source_fingerprint, tight_temporal |
| 18 | 22 | 0.75 | linguistic_overlap_high, matched_term_temporal, shared_source_fingerprint, tight_temporal |

## Analyst Action
Immediate escalation to protective detail lead and intelligence manager (target: 30 minutes).

## Reproduce
```bash
make init
PI_ENABLE_TELEGRAM_COLLECTOR=1 PI_ENABLE_CHANS_COLLECTOR=1 PI_ENABLE_SUPPLY_CHAIN=1 python run.py scrape
python scripts/generate_incident_thread_casepack.py
```
