# Sample Synthetic Casepack

Generated: synthetic fixture workflow (`make demo`)

## Detection

- Insider anomaly detected for `EMP-7415` (off-hours access + data movement + communication metadata shift).
- Third-party risk pivot detected for `sc-004` (`Aster Cloud Analytics`) with elevated vendor risk factors.
- External corroboration present through synthetic OSINT bridge event tied to `user_id:emp-7415`.

## Correlated Thread

- `thread_id`: `soi-e5551e4f98fe`
- source types: `insider`, `rss`, `supply_chain`
- convergence pivots: `user_id`, `vendor_id`, `domain`

## Reason Codes and Evidence

- reason codes: `shared_user_id`, `shared_vendor_id`, `cross_source`, `tight_temporal`
- evidence:
  - `user_id:emp-7415`
  - `vendor_id:sc-004`
  - `domain:aster-cloud.example`
  - pair evidence includes insider<->external and insider<->vendor links

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
