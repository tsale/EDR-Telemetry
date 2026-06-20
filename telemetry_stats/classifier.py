from __future__ import annotations

import re
from pathlib import PurePosixPath


CONTEXT_TERMS = {
    "fix": "correction",
    "correction": "correction",
    "inaccurate": "correction",
    "clarify": "clarification",
    "reclassify": "clarification",
    "downgrade": "stricter_evidence",
    "evidence": "needs_manual_review",
    "mistake": "correction",
    "revert": "correction",
}


def classify_status_change(old_status: str | None, new_status: str | None, weighted_delta: float) -> tuple[str, str, list[str]]:
    tags: list[str] = []
    if old_status == "Pending Response" and new_status != "Pending Response":
        tags.append("pending_response_resolved")
    if new_status == "Pending Response" and old_status != "Pending Response":
        tags.append("moved_to_pending_response")

    if weighted_delta > 0:
        return "improved", "coverage_upgrade", tags
    if weighted_delta < 0:
        return "reduced", "coverage_downgrade", tags
    if old_status == "Via EnablingTelemetry" and new_status == "Yes":
        return "neutral", "default_availability_improvement", tags
    if old_status == "Via EventLogs" and new_status == "Partially":
        return "neutral", "eventlogs_reclassification", tags
    if old_status == new_status:
        return "neutral", "rename_only", tags
    return "neutral", "clarification", tags


def possible_context_tags(text: str | None) -> list[str]:
    haystack = (text or "").lower()
    tags: list[str] = []
    for term, tag in CONTEXT_TERMS.items():
        if term in haystack and tag not in tags:
            tags.append(tag)
    return tags


def extract_evidence_types(text: str | None) -> list[str]:
    body = text or ""
    lowered = body.lower()
    evidence: list[str] = []

    def add(kind: str) -> None:
        if kind not in evidence:
            evidence.append(kind)

    if re.search(r"\b(official documentation|official docs|vendor documentation|vendor docs|product documentation|published documentation)\b", lowered):
        add("official_documentation")
    if "![" in body or "screenshot" in lowered or "user-attachments" in lowered or re.search(r"\.(png|jpe?g|gif)\b", lowered):
        add("screenshots")
    if re.search(r"\b(event\.|eventid|event id|eventsubid|kql|sql|logs?|table|dataset|sanitized)\b", lowered):
        add("sanitized_logs")
    if re.search(r"\b(private documentation|confidential|shared privately|discord evidence|private evidence)\b", lowered):
        add("private_documentation")
    if re.search(r"\b(telemetry generator|atomic red team|controlled test|scripts? from this repo)\b", lowered):
        add("telemetry_generator")
    if not evidence:
        add("unknown")
    return evidence


def classify_non_score_change(paths: list[str]) -> str:
    if not paths:
        return "unknown"
    kinds = {_path_kind(path) for path in paths}
    if kinds <= {"documentation_only"}:
        return "documentation_only"
    if kinds <= {"tooling_only"}:
        return "tooling_only"
    if kinds <= {"documentation_only", "tooling_only"}:
        return "tooling_only"
    return "unknown"


def _path_kind(path: str) -> str:
    pure = PurePosixPath(path)
    lower = path.lower()
    lower_parts = PurePosixPath(lower).parts
    if lower.endswith((".md", ".rst", ".txt")) or pure.parts[:1] == ("docs",) or "readme" in lower:
        return "documentation_only"
    if lower_parts[:1] in {("tools",), (".github",), ("scripts",), ("tests",)}:
        return "tooling_only"
    return "unknown"
