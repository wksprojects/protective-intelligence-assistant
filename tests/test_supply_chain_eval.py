from evals.supply_chain_eval import (
    render_supply_chain_eval_markdown,
    run_supply_chain_evaluation,
)


def test_supply_chain_evaluation_report_shape():
    report = run_supply_chain_evaluation()
    assert report["cases_total"] >= 5
    assert "counts" in report
    assert "metrics" in report
    metrics = report["metrics"]
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1"] <= 1.0


def test_supply_chain_evaluation_markdown():
    report = run_supply_chain_evaluation()
    markdown = render_supply_chain_eval_markdown(report)
    assert "# Supply Chain Risk Evaluation" in markdown
    assert "## Aggregate Metrics" in markdown
    assert "| Profile | Vendor | Score |" in markdown
