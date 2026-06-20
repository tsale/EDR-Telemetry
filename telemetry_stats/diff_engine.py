from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .classifier import classify_status_change, possible_context_tags
from .config import StatsConfig
from .matrix_parser import MatrixCell, MatrixSnapshot
from .scoring import STATUS_SCORE, ScoringModel


@dataclass
class DiffContext:
    repo_full_name: str
    commit_sha: str
    parent_sha: str | None
    commit_date_utc: str
    file_path: str
    platform: str
    change_source_type: str
    public_url: str
    pr_number: int | None = None
    pr_state: str | None = None
    pr_title: str | None = None
    pr_body_excerpt: str | None = None
    pr_draft: bool | None = None
    merged_at_utc: str | None = None
    contributor_login: str | None = None
    commit_message: str | None = None
    maintainer_reviewed: bool = False
    maintainer_reviewed_by: list[str] = field(default_factory=list)
    evidence_type: list[str] = field(default_factory=lambda: ["unknown"])


@dataclass
class DiffResult:
    events: list[dict[str, Any]] = field(default_factory=list)
    manual_review_items: list[dict[str, Any]] = field(default_factory=list)


EVENT_ID_FIELDS = [
    "repo_full_name",
    "commit_sha",
    "platform",
    "file_path",
    "vendor_before",
    "vendor_after",
    "telemetry_feature_category",
    "sub_category",
    "old_status",
    "new_status",
]


def build_change_event_id(event: dict[str, Any]) -> str:
    material = "|".join("" if event.get(field) is None else str(event.get(field)) for field in EVENT_ID_FIELDS)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def diff_snapshots(
    before: MatrixSnapshot,
    after: MatrixSnapshot,
    context: DiffContext,
    scoring: ScoringModel,
    config: StatsConfig,
) -> DiffResult:
    result = DiffResult()
    for warning in [*before.warnings, *after.warnings]:
        result.manual_review_items.append({"reason": warning.get("kind", "warning"), **warning})

    before_keys = set(before.cells)
    after_keys = set(after.cells)
    before_vendors = before.vendors
    before_features = before.feature_keys
    after_features = after.feature_keys

    for key in sorted(before_keys & after_keys):
        old_cell = before.cells[key]
        new_cell = after.cells[key]
        if old_cell.status == new_cell.status and old_cell.vendor_name == new_cell.vendor_name:
            continue
        event = _build_event(old_cell, new_cell, context, scoring, config)
        if old_cell.status == new_cell.status and old_cell.vendor_name != new_cell.vendor_name:
            event["direction"] = "neutral"
            event["change_kind"] = "rename_only"
            event["confidence"] = "high"
            event["notes"] = f"Vendor column renamed from {old_cell.vendor_name} to {new_cell.vendor_name}; telemetry value did not change."
        result.events.append(_finalize_event(event))

    deleted_keys = sorted(before_keys - after_keys)
    new_keys = sorted(after_keys - before_keys)
    rename_events = _detect_unmapped_vendor_renames(before, after, deleted_keys, new_keys, context, scoring, config)
    renamed_old_keys = {old_key for _, old_key, _ in rename_events}
    renamed_new_keys = {new_key for _, _, new_key in rename_events}

    for key in new_keys:
        if key in renamed_new_keys:
            continue
        new_cell = after.cells[key]
        feature_key = (new_cell.telemetry_feature_category, new_cell.sub_category)
        if feature_key not in before_features:
            kind = "new_category_baseline"
            notes = "New telemetry category/sub-category baseline; not counted as ordinary improvement."
        elif new_cell.vendor_canonical_id not in before_vendors:
            kind = "new_vendor_baseline"
            notes = "New vendor baseline; not counted as ordinary improvement."
        else:
            kind = "unknown"
            notes = "New telemetry cell appeared without a new vendor or category."
        event = _build_event(None, new_cell, context, scoring, config, forced_kind=kind, forced_delta=0.0)
        event["notes"] = notes
        if kind == "unknown":
            event["confidence"] = "low"
            result.manual_review_items.append({"reason": "new_cell_unknown_context", "event": event})
        result.events.append(_finalize_event(event))

    for event, old_key, new_key in rename_events:
        result.events.append(_finalize_event(event))

    for key in deleted_keys:
        if key in renamed_old_keys:
            continue
        old_cell = before.cells[key]
        result.manual_review_items.append(
            {
                "reason": "telemetry_cell_deleted",
                "platform": context.platform,
                "file_path": context.file_path,
                "vendor": old_cell.vendor_name,
                "telemetry_feature_category": old_cell.telemetry_feature_category,
                "sub_category": old_cell.sub_category,
                "commit_sha": context.commit_sha,
            }
        )

    return result


def _build_event(
    old_cell: MatrixCell | None,
    new_cell: MatrixCell | None,
    context: DiffContext,
    scoring: ScoringModel,
    config: StatsConfig,
    *,
    forced_kind: str | None = None,
    forced_delta: float | None = None,
) -> dict[str, Any]:
    cell = new_cell or old_cell
    assert cell is not None
    old_status = old_cell.status if old_cell else None
    new_status = new_cell.status if new_cell else None
    old_score = scoring.status_score(old_status)
    new_score = scoring.status_score(new_status)
    weight = scoring.weight_for(context.platform, cell.sub_category)
    official_delta = (new_score - old_score) * weight
    weighted_delta = forced_delta if forced_delta is not None else official_delta
    quality_delta = scoring.quality_score(new_status) - scoring.quality_score(old_status)
    direction, kind, tags = classify_status_change(old_status, new_status, weighted_delta)
    if forced_kind:
        kind = forced_kind
        direction = "neutral"
    context_tags = possible_context_tags(context.commit_message)
    confidence = "high"
    if old_status not in STATUS_SCORE and old_status is not None:
        confidence = "low"
    if new_status not in STATUS_SCORE and new_status is not None:
        confidence = "low"
    if weight == 0:
        context_tags.append("needs_manual_review")

    contributor_class = config.contributor_class(context.contributor_login)
    vendor_claimed = False
    vendor_confidence = "unknown"
    mapped_vendor = config.vendor_for_login(context.contributor_login)
    vendor_canonical_id = (new_cell or old_cell).vendor_canonical_id
    if mapped_vendor and mapped_vendor == vendor_canonical_id:
        vendor_claimed = True
        vendor_confidence = "high"
    elif _pr_body_claims_matching_vendor(context.pr_body_excerpt, new_cell or old_cell, config):
        vendor_claimed = True
        vendor_confidence = "medium"
        if contributor_class in {"external_contributor", "unknown"}:
            contributor_class = "vendor"

    return {
        "repo_full_name": context.repo_full_name,
        "change_source_type": context.change_source_type,
        "pr_number": context.pr_number,
        "pr_state": context.pr_state,
        "commit_sha": context.commit_sha,
        "parent_sha": context.parent_sha,
        "commit_date_utc": context.commit_date_utc,
        "merged_at_utc": context.merged_at_utc,
        "platform": context.platform,
        "file_path": context.file_path,
        "telemetry_feature_category": cell.telemetry_feature_category,
        "sub_category": cell.sub_category,
        "vendor_before": old_cell.vendor_name if old_cell else None,
        "vendor_after": new_cell.vendor_name if new_cell else None,
        "vendor_canonical_id": vendor_canonical_id,
        "vendor_display_name": (new_cell or old_cell).vendor_display_name,
        "old_status": old_status,
        "new_status": new_status,
        "old_status_score": old_score,
        "new_status_score": new_score,
        "sub_category_weight": weight,
        "weighted_score_delta": round(weighted_delta, 6),
        "old_status_quality_score": scoring.quality_score(old_status),
        "new_status_quality_score": scoring.quality_score(new_status),
        "status_quality_delta": quality_delta,
        "direction": direction,
        "change_kind": kind,
        "change_tags": tags,
        "possible_context_tags": sorted(set(context_tags)),
        "contributor_login": context.contributor_login,
        "contributor_class": contributor_class,
        "vendor_affiliation_claimed": vendor_claimed,
        "vendor_affiliation_confidence": vendor_confidence,
        "evidence_type": context.evidence_type or ["unknown"],
        "pr_title": context.pr_title,
        "pr_body_excerpt": context.pr_body_excerpt,
        "commit_message": context.commit_message,
        "maintainer_reviewed": context.maintainer_reviewed,
        "maintainer_reviewed_by": context.maintainer_reviewed_by,
        "public_url": context.public_url,
        "confidence": confidence,
        "notes": _default_notes(old_status, new_status, kind),
    }


def _finalize_event(event: dict[str, Any]) -> dict[str, Any]:
    event["change_event_id"] = build_change_event_id(event)
    return event


def _default_notes(old_status: str | None, new_status: str | None, kind: str) -> str:
    if kind in {"coverage_upgrade", "coverage_downgrade"}:
        return f"Telemetry status changed from {old_status} to {new_status}."
    if kind == "default_availability_improvement":
        return "Official score is unchanged, but telemetry moved from enabling-required to default Yes."
    if kind == "eventlogs_reclassification":
        return "Official score is unchanged, but status moved from Via EventLogs to Partially."
    return f"Telemetry cell classified as {kind}."


def _detect_unmapped_vendor_renames(
    before: MatrixSnapshot,
    after: MatrixSnapshot,
    deleted_keys: list[tuple[str, str, str]],
    new_keys: list[tuple[str, str, str]],
    context: DiffContext,
    scoring: ScoringModel,
    config: StatsConfig,
) -> list[tuple[dict[str, Any], tuple[str, str, str], tuple[str, str, str]]]:
    events: list[tuple[dict[str, Any], tuple[str, str, str], tuple[str, str, str]]] = []
    deleted_by_feature = {(cat, sub): key for cat, sub, vendor in deleted_keys for key in [(cat, sub, vendor)]}
    new_by_feature = {(cat, sub): key for cat, sub, vendor in new_keys for key in [(cat, sub, vendor)]}
    shared_features = set(deleted_by_feature) & set(new_by_feature)
    if not shared_features:
        return events
    for feature in sorted(shared_features):
        old_key = deleted_by_feature[feature]
        new_key = new_by_feature[feature]
        old_cell = before.cells[old_key]
        new_cell = after.cells[new_key]
        if old_cell.status != new_cell.status:
            continue
        event = _build_event(old_cell, new_cell, context, scoring, config, forced_kind="rename_only", forced_delta=0.0)
        event["direction"] = "neutral"
        event["confidence"] = "medium"
        event["notes"] = f"Possible vendor rename from {old_cell.vendor_name} to {new_cell.vendor_name}; telemetry value was identical."
        events.append((event, old_key, new_key))
    return events


def _pr_body_claims_matching_vendor(text: str | None, cell: MatrixCell, config: StatsConfig) -> bool:
    if not text:
        return False
    names = {cell.vendor_name, cell.vendor_display_name, cell.vendor_canonical_id.replace("_", " ")}
    alias = config.vendor_aliases.get(cell.vendor_canonical_id)
    if alias:
        names.add(alias.display_name)
        names.update(alias.aliases)
    for name in sorted({value.strip() for value in names if value and len(value.strip()) > 2}, key=len, reverse=True):
        escaped = re_escape_words(name)
        patterns = [
            rf"\b(?:i|we)\s+(?:work|working)\s+(?:for|at|with)\s+{escaped}\b",
            rf"\b(?:i am|i'm|we are|we're)\s+(?:an?\s+)?{escaped}\s+(?:employee|engineer|representative|team member)\b",
            rf"\b{escaped}\s+(?:employee|engineer|representative|team)\b",
            rf"\bvendor\s*:\s*{escaped}\b",
        ]
        lowered = text.lower()
        if any(re.search(pattern, lowered) for pattern in patterns):
            return True
    return False


def re_escape_words(value: str) -> str:
    return r"\s+".join(re.escape(part.lower()) for part in value.split())
