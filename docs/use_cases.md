# Investigation Use Cases

This project models investigation workflows with synthetic, de-identified data.

## Insider investigation triage

- **Trigger:** behavioral anomalies in fixture-driven telemetry simulation.
- **Core signals:** off-hours access, data movement spikes, badge/logical mismatch, communication metadata shift.
- **Analyst output:** IRS reason codes + investigation thread pivots + casepack context.

## Third-party access misuse

- **Trigger:** elevated vendor exposure profile in the supply-chain scaffold.
- **Core signals:** concentration risk, privilege scope, sensitive data exposure, compliance posture.
- **Analyst output:** vendor risk tier + factor breakdown + linked entities in investigation threads.

## Converged cyber/physical/human signal threading

- **Trigger:** shared identifiers or temporal overlap across external, insider, and vendor signals.
- **Core pivots:** `user_id`, `device_id`, `vendor_id`, `domain`, `ipv4`, `url`.
- **Analyst output:** explainable thread confidence, pair evidence, provenance keys, disposition-ready context.
