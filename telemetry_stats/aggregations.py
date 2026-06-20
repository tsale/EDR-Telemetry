from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from .config import StatsConfig
from .matrix_parser import MatrixSnapshot, parse_matrix_content
from .scoring import ScoringModel


SCORE_COUNTED_KINDS = {
    "coverage_upgrade",
    "coverage_downgrade",
    "default_availability_improvement",
    "eventlogs_reclassification",
    "clarification",
}


def current_vendor_scores(repo: Path, config: StatsConfig, scoring: ScoringModel) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for platform, file_name in [
        ("windows", "EDR_telem_windows.json"),
        ("linux", "EDR_telem_linux.json"),
        ("macos", "EDR_telem_macOS.json"),
    ]:
        path = repo / file_name
        if not path.exists():
            continue
        snapshot = parse_matrix_content(path.read_text(encoding="utf-8"), platform=platform, file_path=file_name, config=config)
        scores: dict[str, float] = defaultdict(float)
        display_names: dict[str, str] = {}
        for cell in snapshot.cells.values():
            scores[cell.vendor_canonical_id] += scoring.status_score(cell.status) * scoring.weight_for(platform, cell.sub_category)
            display_names[cell.vendor_canonical_id] = cell.vendor_display_name
        for vendor_id, score in sorted(scores.items(), key=lambda item: (-item[1], item[0])):
            rows.append(
                {
                    "vendor_canonical_id": vendor_id,
                    "vendor_display_name": display_names.get(vendor_id, vendor_id),
                    "platform": platform,
                    "score": round(score, 2),
                }
            )
    return rows


def vendor_score_timeseries(events: list[dict[str, Any]], scoring: ScoringModel) -> list[dict[str, Any]]:
    contributions: dict[tuple[str, str, str, str, str], float] = {}
    points_by_vendor: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    display_names: dict[str, str] = {}

    for event in sorted(events, key=lambda item: (item.get("commit_date_utc") or "", item.get("commit_sha") or "", item.get("change_event_id") or "")):
        vendor_id = event["vendor_canonical_id"]
        platform = event["platform"]
        display_names[vendor_id] = event.get("vendor_display_name") or vendor_id
        cell_key = (
            vendor_id,
            platform,
            event["telemetry_feature_category"],
            event["sub_category"],
            event["file_path"],
        )
        if event.get("new_status") is not None:
            contributions[cell_key] = scoring.status_score(event.get("new_status")) * float(event.get("sub_category_weight") or 0)
        else:
            contributions.pop(cell_key, None)
        current_score = sum(value for key, value in contributions.items() if key[0] == vendor_id and key[1] == platform)
        points_by_vendor[(vendor_id, platform)].append(
            {
                "date": _date_only(event.get("commit_date_utc")),
                "score": round(current_score, 2),
                "score_delta": round(float(event.get("weighted_score_delta") or 0), 6),
                "source_pr": event.get("pr_number"),
                "source_commit": event.get("commit_sha"),
                "change_kind": event.get("change_kind"),
            }
        )

    return [
        {
            "vendor_canonical_id": vendor_id,
            "vendor_display_name": display_names.get(vendor_id, vendor_id),
            "platform": platform,
            "points": points,
        }
        for (vendor_id, platform), points in sorted(points_by_vendor.items())
    ]


def vendor_change_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for event in events:
        vendor_id = event["vendor_canonical_id"]
        item = summary.setdefault(
            vendor_id,
            {
                "vendor_canonical_id": vendor_id,
                "vendor_display_name": event.get("vendor_display_name") or vendor_id,
                "total_accepted_changed_telemetry_cells": 0,
                "positive_weighted_score_delta": 0.0,
                "negative_weighted_score_delta": 0.0,
                "net_weighted_score_delta": 0.0,
                "prs_affecting_vendor": set(),
                "direct_commits_affecting_vendor": set(),
                "categories_touched": set(),
                "pending_response_values_resolved": 0,
                "corrections_or_downgrades": 0,
                "default_availability_improvements": 0,
            },
        )
        item["total_accepted_changed_telemetry_cells"] += 1
        delta = float(event.get("weighted_score_delta") or 0)
        if delta > 0:
            item["positive_weighted_score_delta"] += delta
        if delta < 0:
            item["negative_weighted_score_delta"] += delta
        item["net_weighted_score_delta"] += delta
        if event.get("pr_number"):
            item["prs_affecting_vendor"].add(event["pr_number"])
        if event.get("change_source_type") == "direct_commit":
            item["direct_commits_affecting_vendor"].add(event["commit_sha"])
        item["categories_touched"].add(event["telemetry_feature_category"])
        if "pending_response_resolved" in (event.get("change_tags") or []):
            item["pending_response_values_resolved"] += 1
        if event.get("change_kind") == "coverage_downgrade" or "correction" in (event.get("possible_context_tags") or []):
            item["corrections_or_downgrades"] += 1
        if event.get("change_kind") == "default_availability_improvement":
            item["default_availability_improvements"] += 1

    return [_finalize_vendor_summary(item) for item in sorted(summary.values(), key=lambda row: row["vendor_canonical_id"])]


def category_change_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        key = (event["telemetry_feature_category"], event["sub_category"])
        item = summary.setdefault(
            key,
            {
                "telemetry_feature_category": key[0],
                "sub_category": key[1],
                "number_of_improvements": 0,
                "total_weighted_score_delta": 0.0,
                "vendors_affected": set(),
                "platforms_affected": set(),
                "first_improvement_date": None,
                "latest_improvement_date": None,
            },
        )
        delta = float(event.get("weighted_score_delta") or 0)
        item["total_weighted_score_delta"] += delta
        item["vendors_affected"].add(event["vendor_canonical_id"])
        item["platforms_affected"].add(event["platform"])
        if delta > 0:
            item["number_of_improvements"] += 1
            date = _date_only(event.get("commit_date_utc"))
            if item["first_improvement_date"] is None or date < item["first_improvement_date"]:
                item["first_improvement_date"] = date
            if item["latest_improvement_date"] is None or date > item["latest_improvement_date"]:
                item["latest_improvement_date"] = date
    return [_finalize_category_summary(item) for item in sorted(summary.values(), key=lambda row: (row["telemetry_feature_category"], row["sub_category"]))]


def contributor_summary(events: list[dict[str, Any]], prs: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for pr in prs or []:
        login = (pr.get("user") or {}).get("login") or "unknown"
        item = summary.setdefault(
            login,
            {
                "contributor_login": login,
                "contributor_class": "unknown",
                "prs_opened": set(),
                "merged_prs": set(),
                "direct_commits": set(),
                "changed_telemetry_cells": 0,
                "positive_score_delta": 0.0,
                "negative_score_delta": 0.0,
                "vendors_affected": set(),
                "evidence_types_used": set(),
            },
        )
        if pr.get("number") is not None:
            item["prs_opened"].add(pr["number"])
            if pr.get("merged_at"):
                item["merged_prs"].add(pr["number"])

    for event in events:
        login = event.get("contributor_login") or "unknown"
        item = summary.setdefault(
            login,
            {
                "contributor_login": login,
                "contributor_class": event.get("contributor_class") or "unknown",
                "prs_opened": set(),
                "merged_prs": set(),
                "direct_commits": set(),
                "changed_telemetry_cells": 0,
                "positive_score_delta": 0.0,
                "negative_score_delta": 0.0,
                "vendors_affected": set(),
                "evidence_types_used": set(),
            },
        )
        if event.get("pr_number"):
            item["prs_opened"].add(event["pr_number"])
            if event.get("merged_at_utc"):
                item["merged_prs"].add(event["pr_number"])
        if event.get("change_source_type") == "direct_commit":
            item["direct_commits"].add(event["commit_sha"])
        item["changed_telemetry_cells"] += 1
        delta = float(event.get("weighted_score_delta") or 0)
        if delta > 0:
            item["positive_score_delta"] += delta
        if delta < 0:
            item["negative_score_delta"] += delta
        item["vendors_affected"].add(event["vendor_canonical_id"])
        for evidence in event.get("evidence_type") or []:
            item["evidence_types_used"].add(evidence)
    return [_finalize_contributor_summary(item) for item in sorted(summary.values(), key=lambda row: row["contributor_login"])]


def pr_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: dict[int, dict[str, Any]] = {}
    for event in events:
        pr_number = event.get("pr_number")
        if pr_number is None:
            continue
        item = summary.setdefault(
            pr_number,
            {
                "pr_number": pr_number,
                "title": event.get("pr_title"),
                "state": event.get("pr_state"),
                "draft": None,
                "created_at": None,
                "merged_at": event.get("merged_at_utc"),
                "author": event.get("contributor_login"),
                "changed_score_bearing_files": set(),
                "changed_telemetry_cells": 0,
                "score_delta": 0.0,
                "vendors_affected": set(),
                "categories_affected": set(),
                "evidence_types": set(),
                "maintainer_reviewed": event.get("maintainer_reviewed"),
                "public_url": event.get("public_url"),
            },
        )
        item["changed_score_bearing_files"].add(event["file_path"])
        item["changed_telemetry_cells"] += 1
        item["score_delta"] += float(event.get("weighted_score_delta") or 0)
        item["vendors_affected"].add(event["vendor_canonical_id"])
        item["categories_affected"].add(event["telemetry_feature_category"])
        for evidence in event.get("evidence_type") or []:
            item["evidence_types"].add(evidence)
    return [_finalize_pr_summary(item) for item in sorted(summary.values(), key=lambda row: row["pr_number"])]


def direct_commit_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("change_source_type") != "direct_commit":
            continue
        sha = event["commit_sha"]
        item = summary.setdefault(
            sha,
            {
                "commit_sha": sha,
                "commit_date_utc": event.get("commit_date_utc"),
                "commit_message": event.get("commit_message"),
                "author": event.get("contributor_login"),
                "changed_score_bearing_files": set(),
                "changed_telemetry_cells": 0,
                "score_delta": 0.0,
                "vendors_affected": set(),
                "categories_affected": set(),
                "public_url": event.get("public_url"),
            },
        )
        item["changed_score_bearing_files"].add(event["file_path"])
        item["changed_telemetry_cells"] += 1
        item["score_delta"] += float(event.get("weighted_score_delta") or 0)
        item["vendors_affected"].add(event["vendor_canonical_id"])
        item["categories_affected"].add(event["telemetry_feature_category"])
    return [_finalize_direct_commit_summary(item) for item in sorted(summary.values(), key=lambda row: row["commit_sha"])]


def _date_only(value: str | None) -> str | None:
    if not value:
        return None
    return value[:10]


def _sorted_list(value: set[Any]) -> list[Any]:
    return sorted(value)


def _finalize_vendor_summary(item: dict[str, Any]) -> dict[str, Any]:
    item = dict(item)
    item["number_of_prs_affecting_vendor"] = len(item.pop("prs_affecting_vendor"))
    item["number_of_direct_commits_affecting_vendor"] = len(item.pop("direct_commits_affecting_vendor"))
    item["number_of_categories_touched"] = len(item.pop("categories_touched"))
    for key in ["positive_weighted_score_delta", "negative_weighted_score_delta", "net_weighted_score_delta"]:
        item[key] = round(item[key], 6)
    return item


def _finalize_category_summary(item: dict[str, Any]) -> dict[str, Any]:
    item = dict(item)
    item["vendors_affected"] = _sorted_list(item["vendors_affected"])
    item["platforms_affected"] = _sorted_list(item["platforms_affected"])
    item["total_weighted_score_delta"] = round(item["total_weighted_score_delta"], 6)
    return item


def _finalize_contributor_summary(item: dict[str, Any]) -> dict[str, Any]:
    item = dict(item)
    item["prs_opened"] = len(item["prs_opened"])
    item["merged_prs"] = len(item["merged_prs"])
    item["direct_commits"] = len(item["direct_commits"])
    item["vendors_affected"] = _sorted_list(item["vendors_affected"])
    item["evidence_types_used"] = _sorted_list(item["evidence_types_used"])
    item["positive_score_delta"] = round(item["positive_score_delta"], 6)
    item["negative_score_delta"] = round(item["negative_score_delta"], 6)
    return item


def _finalize_pr_summary(item: dict[str, Any]) -> dict[str, Any]:
    item = dict(item)
    for key in ["changed_score_bearing_files", "vendors_affected", "categories_affected", "evidence_types"]:
        item[key] = _sorted_list(item[key])
    item["score_delta"] = round(item["score_delta"], 6)
    return item


def _finalize_direct_commit_summary(item: dict[str, Any]) -> dict[str, Any]:
    item = dict(item)
    for key in ["changed_score_bearing_files", "vendors_affected", "categories_affected"]:
        item[key] = _sorted_list(item[key])
    item["score_delta"] = round(item["score_delta"], 6)
    return item
