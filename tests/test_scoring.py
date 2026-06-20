from pathlib import Path

from telemetry_stats.scoring import (
    STATUS_QUALITY_SCORE,
    STATUS_SCORE,
    ScoringModel,
    load_scoring_from_compare_py,
)


def test_status_scores_preserve_official_and_quality_scales():
    assert STATUS_SCORE["Via EnablingTelemetry"] == 1.0
    assert STATUS_SCORE["Pending Response"] == 0.0
    assert STATUS_QUALITY_SCORE["Via EnablingTelemetry"] == 2
    assert STATUS_QUALITY_SCORE["Yes"] == 3


def test_loads_feature_weights_from_compare_py_with_ast(tmp_path: Path):
    compare_py = tmp_path / "compare.py"
    compare_py.write_text(
        """
FEATURES_DICT_VALUED = {"Yes": 1, "No": 0}
WINDOWS_CATEGORIES_VALUED = {"Process Creation": 1, "Process Termination": 0.5}
LINUX_CATEGORIES_VALUED = {"DNS Query": 1}
MACOS_CATEGORIES_VALUED = {"Launchd Item Created": 1.0}
""",
        encoding="utf-8",
    )

    model = load_scoring_from_compare_py(compare_py)

    assert isinstance(model, ScoringModel)
    assert model.weight_for("windows", "Process Termination") == 0.5
    assert model.weight_for("linux", "DNS Query") == 1.0
    assert model.weight_for("macos", "Launchd Item Created") == 1.0
