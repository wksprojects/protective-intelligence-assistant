from evals.benchmark import build_benchmark_metrics, render_benchmark_markdown
from processor.correlation import build_incident_threads


def test_processor_correlation_facade_returns_list():
    threads = build_incident_threads(days=7, window_hours=72, min_cluster_size=2, limit=10)
    assert isinstance(threads, list)


def test_evals_benchmark_metrics_shape_and_markdown():
    metrics = build_benchmark_metrics()
    assert "n_cases" in metrics
    assert metrics["n_cases"] >= 30
    assert "severity_accuracy" in metrics
    assert "escalation_quality" in metrics

    markdown = render_benchmark_markdown(metrics)
    assert "# Benchmark Table" in markdown
    assert "| Model | Accuracy |" in markdown
    assert "| Model | Precision | Recall | F1 | False Positives |" in markdown
