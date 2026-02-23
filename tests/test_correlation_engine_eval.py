from evals.correlation_engine_eval import (
    render_correlation_engine_eval_markdown,
    run_correlation_engine_evaluation,
)


def test_correlation_engine_evaluation_report_shape():
    report = run_correlation_engine_evaluation()
    assert report["cases_total"] >= 6
    assert report["pair_totals"]["support_positive_pairs"] > 0
    assert report["pair_totals"]["support_all_pairs"] > 0
    assert 0.0 <= report["aggregate"]["precision"] <= 1.0
    assert 0.0 <= report["aggregate"]["recall"] <= 1.0
    assert 0.0 <= report["aggregate"]["f1"] <= 1.0
    assert len(report["cases"]) == report["cases_total"]


def test_correlation_engine_evaluation_markdown():
    report = run_correlation_engine_evaluation()
    markdown = render_correlation_engine_eval_markdown(report)
    assert "# Correlation Engine Evaluation" in markdown
    assert "## Aggregate Pairwise Metrics" in markdown
    assert "| Case | Alerts | Expected Pairs | Predicted Pairs |" in markdown
