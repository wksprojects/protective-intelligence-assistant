#!/usr/bin/env python3
"""Generate supply-chain scaffold precision/recall artifact from fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evals.supply_chain_eval import (  # noqa: E402
    render_supply_chain_eval_markdown,
    run_supply_chain_evaluation,
)


def main():
    report = run_supply_chain_evaluation()
    output = Path("docs/supply_chain_eval.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_supply_chain_eval_markdown(report), encoding="utf-8")

    metrics = report["metrics"]
    print(f"Supply-chain eval written: {output}")
    print(f"  Cases: {report['cases_total']}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall: {metrics['recall']:.4f}")
    print(f"  F1: {metrics['f1']:.4f}")


if __name__ == "__main__":
    main()
