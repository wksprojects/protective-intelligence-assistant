"""Evaluation package boundary."""

from evals.benchmark import build_benchmark_metrics, render_benchmark_markdown
from evals.correlation_engine_eval import (
    render_correlation_engine_eval_markdown,
    run_correlation_engine_evaluation,
)
from evals.insider_risk_eval import (
    render_insider_risk_eval_markdown,
    run_insider_risk_evaluation,
)
from evals.signal_quality import compute_signal_quality_view
from evals.source_health_heartbeat import (
    build_source_health_heartbeat,
    render_source_health_heartbeat_markdown,
    write_source_health_heartbeat_artifacts,
)
from evals.supply_chain_eval import (
    render_supply_chain_eval_markdown,
    run_supply_chain_evaluation,
)

__all__ = [
    "build_benchmark_metrics",
    "render_benchmark_markdown",
    "run_correlation_engine_evaluation",
    "render_correlation_engine_eval_markdown",
    "run_insider_risk_evaluation",
    "render_insider_risk_eval_markdown",
    "run_supply_chain_evaluation",
    "render_supply_chain_eval_markdown",
    "compute_signal_quality_view",
    "build_source_health_heartbeat",
    "render_source_health_heartbeat_markdown",
    "write_source_health_heartbeat_artifacts",
]
