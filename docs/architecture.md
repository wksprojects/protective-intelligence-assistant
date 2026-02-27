# Architecture Overview

## Pipeline

Inputs -> normalization -> correlation -> scoring -> artifacts

```mermaid
flowchart LR
    A["Inputs: external OSINT + insider telemetry sim + vendor profiles"] --> B["Normalization"]
    B --> C["Entity/Pivot Extraction"]
    C --> D["Investigation Thread Correlation"]
    D --> E["Scoring: ORS / TAS / IRS / Vendor Risk"]
    E --> F["Artifacts: queues, casepack, SITREP"]
```

## Components

- **Inputs:** fixture-first collectors and ingest endpoints.
- **Normalization:** common alert/entity representation, dedup, source metadata.
- **Correlation:** SOI thread engine with reason-coded pair evidence.
- **Scoring:** explainable weighted scoring across operational, threat, insider, and vendor dimensions.
- **Artifacts:** analyst outputs for triage and escalation (`/analytics/*`, casepack, SITREP).

## Evidence and accountability

- reason codes
- pair evidence
- provenance keys
- mutation audit trail (`audit_log`)
