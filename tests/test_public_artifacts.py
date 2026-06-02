from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_public_review_artifacts_are_present():
    expected = [
        "outputs/summary.md",
        "outputs/review_queue.csv",
        "outputs/entity_or_event_rollup.csv",
        "docs/methodology.md",
        "docs/limitations.md",
        "docs/public_companion_casepack.md",
    ]

    for relative_path in expected:
        path = PROJECT_ROOT / relative_path
        assert path.exists(), f"Missing review artifact: {relative_path}"
        assert path.read_text(encoding="utf-8").strip()


def test_dependency_metadata_has_no_local_file_references():
    checked_files = [
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
    ]
    optional_lock = PROJECT_ROOT / "requirements.lock"
    if optional_lock.exists():
        checked_files.append("requirements.lock")

    for relative_path in checked_files:
        content = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        assert "file://" not in content
        assert "/AppleInternal/" not in content
        assert "/Users/" not in content
