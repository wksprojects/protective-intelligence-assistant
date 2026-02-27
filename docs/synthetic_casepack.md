# Synthetic Casepack (Compact)

Generated from synthetic fixture data to show end-to-end investigative workflow in a public-safe format.

## 1) Detection

- **Insider signal:** `EMP-7415` triggered high IRS telemetry pattern:
  - off-hours privileged access
  - staged data movement indicators
  - communication metadata shift
- **Vendor/third-party pivot:** `sc-004` (`Aster Cloud Analytics`) scored elevated vendor risk and appeared in correlated thread entities.
- **External corroboration:** one synthetic external bridge alert linked `user_id:emp-7415` and `vendor_id:sc-004`.

## 2) Thread Formation

- `thread_id`: `soi-e5551e4f98fe`
- Source types in thread: `insider`, `rss`, `supply_chain`
- Correlation outcome: insider telemetry, external signal, and vendor risk artifacts clustered into one SOI thread.

## 3) Reason Codes and Evidence

Primary reason codes:

- `shared_user_id`
- `shared_vendor_id`
- `cross_source`
- `tight_temporal`

Evidence snapshots:

- Shared entities: `user_id:emp-7415`, `vendor_id:sc-004`, `domain:aster-cloud.example`
- Pairwise linkage sample:
  - insider alert <-> external bridge alert (reason: `shared_user_id`, `cross_source`)
  - insider alert <-> supply-chain alert (reason: `shared_vendor_id`, `cross_source`)

## 4) Analyst Disposition

- **Disposition:** `true_positive`
- **Escalation:** `CRITICAL` (immediate escalation window)
- **Action taken:** open investigative case, preserve artifacts, notify protective detail lead + intel manager.

## Reproduce Full Artifact

```bash
make casepack
```

Full threaded output is written to `docs/incident_thread_casepack.md`.
