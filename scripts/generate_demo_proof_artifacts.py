#!/usr/bin/env python3
"""Generate compact proof artifacts for README reviewer path."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "docs"
OUT_DIR = ROOT / "out"
CASEPACK_PATH = DOCS_DIR / "sample_casepack.md"
SITREP_PATH = OUT_DIR / "sitrep.md"


def render_casepack() -> str:
    return """# Sample Synthetic Casepack

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
"""


def render_sitrep() -> str:
    return """# SITREP (Synthetic)

Generated: synthetic fixture workflow (`make demo`)
Classification: Synthetic/Unclassified

## Summary
Cross-domain correlation surfaced an elevated protective-intelligence thread linking insider telemetry, external signal activity, and third-party vendor exposure.

## Key Facts
- subject pivot: `EMP-7415`
- vendor pivot: `sc-004`
- thread confidence: high (synthetic fixture scenario)
- principal risk: potential insider-enabled data staging/exfil pathway

## Current Assessment
Credible convergence indicators justify immediate escalation and controlled mitigation actions.

## Immediate Actions
1. Enforce temporary access constraints on implicated identities/systems.
2. Escalate to protective detail lead and intelligence manager.
3. Preserve event/provenance artifacts for investigative continuity.
"""


def main() -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    CASEPACK_PATH.write_text(render_casepack(), encoding="utf-8")
    SITREP_PATH.write_text(render_sitrep(), encoding="utf-8")

    print("Generated proof artifacts:")
    print(f"  - {CASEPACK_PATH}")
    print(f"  - {SITREP_PATH}")


if __name__ == "__main__":
    main()
