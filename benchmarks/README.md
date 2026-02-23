# Benchmarks

This directory documents reproducible evaluation assets for the Protective Intelligence Assistant.

## Correlation Engine Benchmark

- Ground-truth dataset: `fixtures/correlation_eval_cases.json`
- Runner: `scripts/generate_correlation_eval.py`
- Output artifact: `docs/correlation_eval.md`

Run:

```bash
make correlation-eval
```

Notes:

- Metrics are computed on pairwise linkage outcomes (TP/FP/FN/TN over alert pairs).
- Dataset intentionally includes ambiguous/adversarial near-miss cases to avoid inflated scores.

## Scoring/Model Benchmark

- Runner: `scripts/generate_benchmark_table.py`
- Output artifact: `docs/benchmark_table.md`

Run:

```bash
make benchmark
```

## Reliability Benchmark (Heartbeat)

- Runner: `scripts/generate_source_health_heartbeat.py`
- Output snapshot: `docs/source_health_heartbeat.md`
- Output log: `docs/source_health_heartbeat.jsonl` (append-only log)

Run:

```bash
make heartbeat
```
