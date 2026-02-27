#!/usr/bin/env python3
"""Generate compact proof artifacts for README reviewer path."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analytics.insider_risk import list_insider_risk
from analytics.supply_chain_risk import list_supply_chain_risk
from processor.correlation import build_incident_threads

DOCS_DIR = ROOT / "docs"
OUT_DIR = ROOT / "out"
CASEPACK_PATH = DOCS_DIR / "sample_casepack.md"
SITREP_PATH = OUT_DIR / "sitrep.md"


def _select_thread(threads):
    if not threads:
        return None

    def _score(thread):
        source_types = set(thread.get("source_types") or [])
        reasons = set(thread.get("reason_codes") or [])
        score = 0
        if "insider" in source_types:
            score += 2
        if "supply_chain" in source_types:
            score += 2
        if {"rss", "reddit", "pastebin", "telegram", "chans"}.intersection(source_types):
            score += 1
        if "shared_user_id" in reasons:
            score += 2
        if "shared_vendor_id" in reasons:
            score += 2
        score += float(thread.get("thread_confidence") or 0.0)
        return score

    return sorted(threads, key=_score, reverse=True)[0]


def _risk_disposition(thread):
    confidence = float(thread.get("thread_confidence") or 0.0)
    max_ors = float(thread.get("max_ors_score") or 0.0)
    if confidence >= 0.75 or max_ors >= 85.0:
        return "true_positive", "CRITICAL"
    if confidence >= 0.5 or max_ors >= 65.0:
        return "monitor_escalated", "ELEVATED"
    return "monitor", "ROUTINE"


def _format_entities(shared_entities):
    pivots = []
    for item in shared_entities or []:
        text = str(item)
        if text.startswith(("user_id:", "device_id:", "vendor_id:", "domain:")):
            pivots.append(text)
    if not pivots:
        pivots = list(shared_entities or [])[:4]
    return pivots[:4]


def render_casepack(thread, insider_row, vendor_row, disposition, tier) -> str:
    reason_codes = (thread.get("reason_codes") or [])[:6]
    source_types = ", ".join(thread.get("source_types") or [])
    pivots = _format_entities(thread.get("shared_entities") or [])
    insider_subject = insider_row.get("subject_id") if insider_row else "n/a"
    vendor_profile = vendor_row.get("profile_id") if vendor_row else "n/a"
    vendor_name = vendor_row.get("vendor_name") if vendor_row else "n/a"
    thread_id = thread.get("thread_id", "n/a")

    return f"""# Sample Synthetic Casepack

Generated: synthetic fixture workflow (`make demo`)

## Detection

- Insider anomaly queue hit for `{insider_subject}` with elevated IRS indicators.
- Third-party risk pivot detected for `{vendor_profile}` (`{vendor_name}`).
- Correlation engine identified cross-source linkage candidates in the current dataset.

## Correlated Thread

- `thread_id`: `{thread_id}`
- source types: `{source_types}`
- convergence pivots: {", ".join(pivots) if pivots else "n/a"}

## Reason Codes and Evidence

- reason codes: {", ".join(f"`{rc}`" for rc in reason_codes) if reason_codes else "n/a"}
- evidence:
{chr(10).join(f"  - `{pivot}`" for pivot in pivots) if pivots else "  - no pivot entities captured"}
  - pair evidence captured in investigation thread output (`pair_evidence`)

## Disposition

- analyst disposition: `{disposition}`
- escalation tier: `{tier}`
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


def render_sitrep(thread, disposition, tier) -> str:
    thread_id = thread.get("thread_id", "n/a")
    reason_codes = (thread.get("reason_codes") or [])[:5]
    pivots = _format_entities(thread.get("shared_entities") or [])

    return f"""# SITREP (Synthetic)

Generated: synthetic fixture workflow (`make demo`)
Classification: Synthetic/Unclassified

## Summary
Cross-domain correlation surfaced an elevated protective-intelligence thread suitable for analyst escalation review.

## Key Facts
- thread id: `{thread_id}`
- source types: {", ".join(thread.get("source_types") or [])}
- reason codes: {", ".join(reason_codes) if reason_codes else "n/a"}
- pivots: {", ".join(pivots) if pivots else "n/a"}

## Current Assessment
Disposition `{disposition}` with escalation tier `{tier}` based on confidence and correlated risk context.

## Immediate Actions
1. Enforce temporary access constraints on implicated identities/systems.
2. Escalate to protective detail lead and intelligence manager.
3. Preserve event/provenance artifacts for investigative continuity.
"""


def main() -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    threads = build_incident_threads(days=30, window_hours=168, min_cluster_size=2, limit=50, include_demo=False)
    thread = _select_thread(threads) or {}
    insider_rows = list_insider_risk(limit=20)
    vendor_rows = list_supply_chain_risk(limit=20)
    insider_row = insider_rows[0] if insider_rows else None
    vendor_row = vendor_rows[0] if vendor_rows else None
    disposition, tier = _risk_disposition(thread)

    CASEPACK_PATH.write_text(
        render_casepack(thread, insider_row, vendor_row, disposition, tier),
        encoding="utf-8",
    )
    SITREP_PATH.write_text(render_sitrep(thread, disposition, tier), encoding="utf-8")

    print("Generated proof artifacts:")
    print(f"  - {CASEPACK_PATH}")
    print(f"  - {SITREP_PATH}")


if __name__ == "__main__":
    main()
