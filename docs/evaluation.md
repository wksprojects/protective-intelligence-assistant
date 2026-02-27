# Evaluation Repro Guide

This repo provides fixture-based precision/recall/F1 evaluation for key investigation components.

## Run evaluations

```bash
make correlation-eval
make insider-eval
make supplychain-eval
```

Generated artifacts:

- `docs/correlation_eval.md`
- `docs/insider_eval.md`
- `docs/supply_chain_eval.md`

## Method assumptions

- evaluations run on synthetic, hand-labeled fixtures
- labels are designed to include true positives, false positives, and ambiguous/near-miss cases
- scores indicate model behavior on fixture methodology, not production performance claims

## Fixture methodology

- **Correlation:** pairwise linkage scoring against labeled convergence cases.
- **Insider:** IRS threshold classification on behavioral telemetry scenarios.
- **Supply chain:** vendor risk threshold classification on scaffolded vendor profiles.

## Review guidance

- prioritize reason-code quality and linkage evidence interpretability alongside headline metrics
- treat perfect fixture precision/recall as a calibration signal, not field-ground-truth accuracy
