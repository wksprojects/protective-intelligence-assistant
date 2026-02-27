# Sample Synthetic Casepack

Generated: synthetic fixture workflow (`make demo`)

## Detection

- Insider anomaly queue hit for `EMP-1042` with elevated IRS indicators.
- Third-party risk pivot detected for `sc-001` (`Northbridge Identity Operations`).
- Correlation engine identified cross-source linkage candidates in the current dataset.

## Correlated Thread

- `thread_id`: `soi-9425b227fe7a`
- source types: `insider, supply_chain`
- convergence pivots: device_id:lptp-553, device_id:lptp-812, device_id:lptp-991, domain:aster-cloud.example

## Reason Codes and Evidence

- reason codes: `cross_source`, `linguistic_overlap_high`, `linguistic_overlap_medium`, `matched_term_temporal`, `shared_source_fingerprint`, `shared_vendor_id`
- evidence:
  - `device_id:lptp-553`
  - `device_id:lptp-812`
  - `device_id:lptp-991`
  - `domain:aster-cloud.example`
  - pair evidence captured in investigation thread output (`pair_evidence`)

## Disposition

- analyst disposition: `true_positive`
- escalation tier: `CRITICAL`
- decision: open investigative case and preserve supporting artifacts

## Recommended Mitigations

1. Restrict and review privileged access for implicated subject and linked assets.
2. Place high-risk vendor integrations on enhanced monitoring with temporary control checks.
3. Trigger cross-functional IR/legal review and maintain evidence provenance for follow-up actions.

## Reproduce Full Threaded Artifact

```bash
make casepack
```

Full threaded export: `docs/incident_thread_casepack.md`
