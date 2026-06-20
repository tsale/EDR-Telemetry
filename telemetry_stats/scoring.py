from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


STATUS_SCORE = {
    "Yes": 1.0,
    "Via EnablingTelemetry": 1.0,
    "Partially": 0.5,
    "Via EventLogs": 0.5,
    "No": 0.0,
    "Pending Response": 0.0,
}

STATUS_QUALITY_SCORE = {
    "Pending Response": 0,
    "No": 0,
    "Via EventLogs": 1,
    "Partially": 1,
    "Via EnablingTelemetry": 2,
    "Yes": 3,
}


@dataclass
class ScoringModel:
    status_scores: dict[str, float] = field(default_factory=lambda: dict(STATUS_SCORE))
    weights_by_platform: dict[str, dict[str, float]] = field(default_factory=dict)

    def status_score(self, status: str | None) -> float:
        if status is None:
            return 0.0
        return float(self.status_scores.get(status, 0.0))

    def quality_score(self, status: str | None) -> int:
        if status is None:
            return 0
        return int(STATUS_QUALITY_SCORE.get(status, 0))

    def weight_for(self, platform: str, sub_category: str) -> float:
        return float((self.weights_by_platform.get(platform) or {}).get(sub_category, 0.0))


def load_scoring_from_compare_py(path: str | Path) -> ScoringModel:
    return load_scoring_from_compare_source(Path(path).read_text(encoding="utf-8"))


def load_scoring_from_compare_source(source: str) -> ScoringModel:
    tree = ast.parse(source)
    assignments: dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in {
                "FEATURES_DICT_VALUED",
                "WINDOWS_CATEGORIES_VALUED",
                "LINUX_CATEGORIES_VALUED",
                "MACOS_CATEGORIES_VALUED",
            }:
                assignments[target.id] = ast.literal_eval(node.value)

    status_scores = dict(STATUS_SCORE)
    for key, value in (assignments.get("FEATURES_DICT_VALUED") or {}).items():
        status_scores[str(key)] = float(value)

    return ScoringModel(
        status_scores=status_scores,
        weights_by_platform={
            "windows": _float_dict(assignments.get("WINDOWS_CATEGORIES_VALUED") or {}),
            "linux": _float_dict(assignments.get("LINUX_CATEGORIES_VALUED") or {}),
            "macos": _float_dict(assignments.get("MACOS_CATEGORIES_VALUED") or {}),
        },
    )


def _float_dict(values: dict[str, Any]) -> dict[str, float]:
    return {str(key): float(value) for key, value in values.items()}
