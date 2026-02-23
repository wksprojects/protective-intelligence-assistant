#!/usr/bin/env python3
"""
Generate a compact benchmark table markdown artifact.

Output:
    docs/benchmark_table.md
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evals.benchmark import build_benchmark_metrics, render_benchmark_markdown


def main():
    metrics = build_benchmark_metrics()
    output = Path("docs/benchmark_table.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_benchmark_markdown(metrics), encoding="utf-8")
    print(f"Benchmark table written: {output}")
    print(f"  Cases: {metrics['n_cases']}")
    print(f"  Rules accuracy: {metrics['severity_accuracy']['rules']:.1%}")
    print(f"  ML accuracy: {metrics['severity_accuracy']['ml']:.1%}")


if __name__ == "__main__":
    main()
