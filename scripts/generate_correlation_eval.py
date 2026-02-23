#!/usr/bin/env python3
"""Generate correlation-engine precision/recall artifact from hand-labeled cases."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evals.correlation_engine_eval import (  # noqa: E402
    run_correlation_engine_evaluation,
    render_correlation_engine_eval_markdown,
)


def main():
    report = run_correlation_engine_evaluation()
    output = Path("docs/correlation_eval.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_correlation_engine_eval_markdown(report), encoding="utf-8")

    aggregate = report["aggregate"]
    print(f"Correlation eval written: {output}")
    print(f"  Cases: {report['cases_total']}")
    print(f"  Precision: {aggregate['precision']:.4f}")
    print(f"  Recall: {aggregate['recall']:.4f}")
    print(f"  F1: {aggregate['f1']:.4f}")


if __name__ == "__main__":
    main()
