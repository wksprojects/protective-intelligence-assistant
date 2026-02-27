from evals.insider_risk_eval import render_insider_risk_eval_markdown, run_insider_risk_evaluation


def test_insider_risk_evaluation_report_shape():
    report = run_insider_risk_evaluation()
    assert report["cases_total"] >= 8
    assert "counts" in report
    assert "metrics" in report
    metrics = report["metrics"]
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1"] <= 1.0


def test_insider_risk_evaluation_markdown():
    report = run_insider_risk_evaluation()
    markdown = render_insider_risk_eval_markdown(report)
    assert "# Insider Risk Evaluation" in markdown
    assert "## Aggregate Metrics" in markdown
    assert "| Scenario | Subject | Score |" in markdown
