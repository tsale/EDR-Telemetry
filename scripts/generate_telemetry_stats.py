#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from telemetry_stats import SCHEMA_VERSION, SCRIPT_VERSION
from telemetry_stats.aggregations import (
    category_change_summary,
    contributor_summary,
    current_vendor_scores,
    direct_commit_summary,
    pr_summary,
    vendor_change_summary,
    vendor_score_timeseries,
)
from telemetry_stats.classifier import classify_non_score_change, extract_evidence_types
from telemetry_stats.config import StatsConfig
from telemetry_stats.diff_engine import DiffContext, diff_snapshots
from telemetry_stats.git_history import (
    ChangedPath,
    changed_paths_for_commit,
    commit_metadata,
    default_branch,
    extract_pr_number_from_commit_message,
    file_at_commit,
    list_commits,
    repo_full_name,
    run_git,
    score_bearing_platform_for_path,
    write_jsonl,
)
from telemetry_stats.github_api import collect_github_metadata
from telemetry_stats.matrix_parser import parse_matrix_content
from telemetry_stats.scoring import ScoringModel, load_scoring_from_compare_py, load_scoring_from_compare_source


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate historical telemetry statistics from Git history.")
    parser.add_argument("--repo", default=".", help="Path to a full checkout of the repository.")
    parser.add_argument("--branch", default=None, help="Branch or revision to scan. Defaults to the current branch.")
    parser.add_argument("--output", default="data/generated", help="Directory for generated public JSON/JSONL files.")
    parser.add_argument("--raw-output", default="data/raw/github", help="Directory for raw/semi-raw GitHub and Git caches.")
    parser.add_argument("--config", default="config/stats_config.yml", help="Stats config YAML.")
    parser.add_argument("--include-open-prs", action="store_true", help="Generate proposed open-PR changes when PR env data is available.")
    parser.add_argument("--github-token-env", default="GITHUB_TOKEN", help="Environment variable containing a GitHub token.")
    parser.add_argument("--refresh-github-cache", action="store_true", help="Refresh GitHub API cache files instead of reusing local raw JSONL files.")
    parser.add_argument("--strict", action="store_true", help="Fail on malformed matrices or unknown statuses.")
    parser.add_argument("--since", default=None, help="Only emit accepted events on or after this ISO date.")
    parser.add_argument("--until", default=None, help="Only emit accepted events on or before this ISO date.")
    parser.add_argument("--format", default="json,jsonl", help="Output formats to emit. JSON/JSONL are supported.")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()
    raw_output = Path(args.raw_output).resolve()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = repo / config_path
    output.mkdir(parents=True, exist_ok=True)
    raw_output.mkdir(parents=True, exist_ok=True)

    config = StatsConfig.load(config_path)
    branch = args.branch or default_branch(repo)
    full_name = repo_full_name(repo)
    github = collect_github_metadata(full_name, raw_output, args.github_token_env, refresh=args.refresh_github_cache)

    events, manual_review, raw_commits, raw_commit_files, warnings = scan_history(
        repo=repo,
        branch=branch,
        repo_full_name_value=full_name,
        config=config,
        github=github,
        strict=args.strict,
        since=args.since,
        until=args.until,
        verbose=args.verbose,
    )
    warnings.extend(github.get("warnings") or [])

    write_jsonl(output / "telemetry_change_events.jsonl", events)
    if "csv" in {item.strip().lower() for item in args.format.split(",")}:
        write_event_csv(output / "telemetry_change_events.csv", events)
    write_json(output / "manual_review_items.json", manual_review)
    write_jsonl(raw_output / "commits.jsonl", raw_commits)
    write_jsonl(raw_output / "commit_files.jsonl", raw_commit_files)

    current_scoring = load_current_scoring(repo, warnings)
    write_json(output / "current_vendor_scores.json", current_vendor_scores(repo, config, current_scoring))
    write_json(output / "vendor_score_timeseries.json", vendor_score_timeseries(events, current_scoring))
    write_json(output / "vendor_change_summary.json", vendor_change_summary(events))
    write_json(output / "category_change_summary.json", category_change_summary(events))
    write_json(output / "contributor_summary.json", contributor_summary(events, github.get("prs") or []))
    write_json(output / "pr_summary.json", enrich_pr_summary(pr_summary(events), github))
    write_json(output / "direct_commit_summary.json", direct_commit_summary(events))
    proposed_changes, proposed_warnings = generate_open_pr_proposed_changes(repo, full_name, config, current_scoring, args, github)
    warnings.extend(proposed_warnings)
    write_json(output / "open_pr_proposed_changes.json", proposed_changes)
    write_json(output / "schema.json", schema_document())

    run_warnings = [*warnings, *_manual_review_warning_summaries(manual_review, per_kind_limit=20)]
    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "repository": full_name,
        "default_branch": branch,
        "head_commit": run_git(repo, ["rev-parse", branch]).strip(),
        "total_commits_scanned": len(raw_commits),
        "total_prs_scanned": len(github.get("prs") or {event.get("pr_number") for event in events if event.get("pr_number")}),
        "total_change_events": len(events),
        "script_version": SCRIPT_VERSION,
        "schema_version": SCHEMA_VERSION,
        "warnings_count": len(warnings) + len(manual_review),
        "warnings": run_warnings[:250],
    }
    write_json(output / "run_metadata.json", metadata)

    if args.verbose:
        print(f"Generated {len(events)} telemetry change events into {output}")
    return 0


def scan_history(
    *,
    repo: Path,
    branch: str,
    repo_full_name_value: str,
    config: StatsConfig,
    github: dict[str, Any],
    strict: bool,
    since: str | None,
    until: str | None,
    verbose: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    commits = list_commits(repo, branch)
    events: list[dict[str, Any]] = []
    manual_review: list[dict[str, Any]] = []
    raw_commits: list[dict[str, Any]] = []
    raw_commit_files: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    previous_scoring: ScoringModel | None = None
    pr_by_merge_commit = {
        pr.get("merge_commit_sha"): int(pr["number"])
        for pr in github.get("prs", [])
        if pr.get("merge_commit_sha") and pr.get("number") is not None
    }
    pr_by_commit = github.get("commit_pr_map") or {}

    for index, sha in enumerate(commits):
        metadata = commit_metadata(repo, sha)
        raw_commits.append(metadata)
        changed_paths = changed_paths_for_commit(repo, sha, metadata["parent_sha"])
        for changed_path in changed_paths:
            raw_commit_files.append(
                {
                    "commit_sha": sha,
                    "status": changed_path.status,
                    "path": changed_path.path,
                    "old_path": changed_path.old_path,
                }
            )

        score_paths = [path for path in changed_paths if _score_platform_for_change(path)]
        if not score_paths:
            kind = classify_non_score_change([path.path for path in changed_paths])
            if kind in {"documentation_only", "tooling_only"}:
                continue
            continue

        if not _date_in_range(metadata["committer_date"], since, until):
            continue

        scoring, scoring_warning = load_scoring_for_commit(repo, sha, previous_scoring)
        previous_scoring = scoring
        if scoring_warning:
            warnings.append(scoring_warning)

        pr_number = extract_pr_number_from_commit_message(metadata["message"]) or pr_by_merge_commit.get(sha) or pr_by_commit.get(sha)
        pr = github.get("pr_by_number", {}).get(pr_number) if pr_number else None
        reviews = github.get("reviews_by_pr", {}).get(pr_number, []) if pr_number else []
        comments = github.get("comments_by_pr", {}).get(pr_number, []) if pr_number else []
        contributor_login = _contributor_login(metadata, pr)
        source_type = _change_source_type(metadata["message"], pr_number)
        evidence_text = "\n\n".join([pr.get("body") or "" if pr else "", *[comment.get("body") or "" for comment in comments]])
        evidence_types = extract_evidence_types(evidence_text)
        reviewed_by = sorted(
            {
                review.get("user", {}).get("login")
                for review in reviews
                if review.get("user", {}).get("login") in config.maintainers and review.get("state") in {"APPROVED", "COMMENTED", "CHANGES_REQUESTED"}
            }
        )

        for changed_path in score_paths:
            platform = _score_platform_for_change(changed_path)
            assert platform is not None
            before_path = changed_path.old_path or changed_path.path
            after_path = changed_path.path
            before_content = file_at_commit(repo, metadata["parent_sha"], before_path)
            after_content = file_at_commit(repo, sha, after_path)
            if before_content is not None and after_content is None:
                manual_review.append(
                    {
                        "reason": "score_bearing_file_deleted",
                        "commit_sha": sha,
                        "parent_sha": metadata["parent_sha"],
                        "platform": platform,
                        "file_path": after_path,
                        "old_path": before_path,
                    }
                )
            context = DiffContext(
                repo_full_name=repo_full_name_value,
                commit_sha=sha,
                parent_sha=metadata["parent_sha"],
                commit_date_utc=metadata["committer_date"],
                file_path=after_path,
                platform=platform,
                change_source_type=source_type,
                public_url=_public_url(repo_full_name_value, sha, pr_number),
                pr_number=pr_number,
                pr_state=_pr_state(pr),
                pr_title=pr.get("title") if pr else None,
                pr_body_excerpt=_excerpt(pr.get("body")) if pr else None,
                pr_draft=pr.get("draft") if pr else None,
                merged_at_utc=pr.get("merged_at") if pr else None,
                contributor_login=contributor_login,
                commit_message=metadata["message"],
                maintainer_reviewed=bool(reviewed_by),
                maintainer_reviewed_by=reviewed_by,
                evidence_type=evidence_types,
            )
            before_snapshot = parse_matrix_content(before_content, platform=platform, file_path=before_path, config=config, strict=strict)
            after_snapshot = parse_matrix_content(after_content, platform=platform, file_path=after_path, config=config, strict=strict)
            diff = diff_snapshots(before_snapshot, after_snapshot, context, scoring, config)
            for event in diff.events:
                if event.get("sub_category_weight") == 0:
                    manual_review.append({"reason": "scoring_weight_missing", "event": event})
                if event.get("change_kind") == "coverage_downgrade":
                    manual_review.append({"reason": "downgrade_or_correction", "event": event})
                if event.get("change_source_type") == "direct_commit" and event.get("contributor_class") == "unknown":
                    manual_review.append({"reason": "direct_commit_by_unknown_contributor", "event": event})
            manual_review.extend(diff.manual_review_items)
            events.extend(diff.events)

        if verbose and (index + 1) % 50 == 0:
            print(f"Scanned {index + 1}/{len(commits)} commits")

    return events, manual_review, raw_commits, raw_commit_files, warnings


def _score_platform_for_change(path: ChangedPath) -> str | None:
    return score_bearing_platform_for_path(path.path) or score_bearing_platform_for_path(path.old_path or "")


def load_scoring_for_commit(repo: Path, sha: str, previous: ScoringModel | None) -> tuple[ScoringModel, dict[str, Any] | None]:
    source = file_at_commit(repo, sha, "Tools/compare.py")
    if source:
        try:
            return load_scoring_from_compare_source(source), None
        except Exception as exc:
            return previous or load_current_scoring(repo, []), {"kind": "scoring_parse_failed", "commit_sha": sha, "message": str(exc)}
    if previous:
        return previous, {"kind": "scoring_fallback_previous", "commit_sha": sha, "message": "Tools/compare.py missing at commit; reused previous scoring model."}
    return load_current_scoring(repo, []), {"kind": "scoring_fallback_worktree", "commit_sha": sha, "message": "Tools/compare.py missing at commit; used working tree scoring model."}


def load_current_scoring(repo: Path, warnings: list[dict[str, Any]]) -> ScoringModel:
    path = repo / "Tools" / "compare.py"
    try:
        return load_scoring_from_compare_py(path)
    except Exception as exc:
        warnings.append({"kind": "current_scoring_parse_failed", "message": str(exc)})
        return ScoringModel()


def generate_open_pr_proposed_changes(
    repo: Path,
    repo_full_name_value: str,
    config: StatsConfig,
    scoring: ScoringModel,
    args: argparse.Namespace,
    github: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not args.include_open_prs and os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        return [], []
    proposed_warnings: list[dict[str, Any]] = []
    api_events = _generate_open_prs_from_api(repo, repo_full_name_value, config, scoring, github, proposed_warnings)
    if api_events:
        return api_events, proposed_warnings

    event_payload = _github_event_payload()
    pull_request = event_payload.get("pull_request") or {}
    base_ref = (pull_request.get("base") or {}).get("sha") or os.environ.get("GITHUB_BASE_REF") or args.branch or default_branch(repo)
    head_ref = (pull_request.get("head") or {}).get("sha") or os.environ.get("GITHUB_HEAD_SHA") or "HEAD"
    merge_base = run_git(repo, ["merge-base", base_ref, head_ref], check=False).strip()
    if not merge_base:
        proposed_warnings.append({"kind": "open_pr_merge_base_missing", "message": "Could not determine merge base for current pull request checkout."})
        return [], proposed_warnings
    diff_output = run_git(repo, ["diff", "--name-status", "-M", merge_base, head_ref], check=False)
    changed_paths = _parse_name_status(diff_output)
    events: list[dict[str, Any]] = []
    for changed_path in changed_paths:
        platform = _score_platform_for_change(changed_path)
        if not platform:
            continue
        before_path = changed_path.old_path or changed_path.path
        before_content = file_at_commit(repo, merge_base, before_path)
        after_content = file_at_commit(repo, head_ref, changed_path.path)
        context = DiffContext(
            repo_full_name=repo_full_name_value,
            commit_sha=head_ref,
            parent_sha=merge_base,
            commit_date_utc=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            file_path=changed_path.path,
            platform=platform,
            change_source_type="pull_request",
            public_url=f"https://github.com/{repo_full_name_value}/pulls",
            pr_number=_env_pr_number(),
            pr_state="draft" if pull_request.get("draft") else "open",
            pr_title=pull_request.get("title"),
            pr_body_excerpt=_excerpt(pull_request.get("body")),
            contributor_login=os.environ.get("GITHUB_ACTOR"),
            commit_message="Open pull request proposed changes",
            evidence_type=["unknown"],
        )
        before_snapshot = parse_matrix_content(before_content, platform=platform, file_path=before_path, config=config)
        after_snapshot = parse_matrix_content(after_content, platform=platform, file_path=changed_path.path, config=config)
        events.extend(diff_snapshots(before_snapshot, after_snapshot, context, scoring, config).events)
    return events, proposed_warnings


def _generate_open_prs_from_api(
    repo: Path,
    repo_full_name_value: str,
    config: StatsConfig,
    scoring: ScoringModel,
    github: dict[str, Any],
    warnings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    open_prs = [pr for pr in github.get("prs", []) if pr.get("state") == "open"]
    for pr in open_prs:
        number = pr.get("number")
        if number is None:
            continue
        tmp_ref = f"refs/telemetry-stats/open-pr-{number}"
        run_git(repo, ["update-ref", "-d", tmp_ref], check=False)
        fetch = run_git(repo, ["fetch", "--force", "origin", f"pull/{number}/head:{tmp_ref}"], check=False)
        if not fetch and run_git(repo, ["rev-parse", "--verify", tmp_ref], check=False).strip() == "":
            warnings.append({"kind": "open_pr_fetch_failed", "pr_number": number, "message": f"Could not fetch pull/{number}/head for proposed-change generation."})
            continue
        base_sha = (pr.get("base") or {}).get("sha")
        if not base_sha:
            base_ref = (pr.get("base") or {}).get("ref") or default_branch(repo)
            base_sha = run_git(repo, ["merge-base", base_ref, tmp_ref], check=False).strip()
        if not base_sha:
            warnings.append({"kind": "open_pr_base_missing", "pr_number": number, "message": "Could not determine base SHA for proposed-change generation."})
            continue
        diff_output = run_git(repo, ["diff", "--name-status", "-M", base_sha, tmp_ref], check=False)
        for changed_path in _parse_name_status(diff_output):
            platform = _score_platform_for_change(changed_path)
            if not platform:
                continue
            before_path = changed_path.old_path or changed_path.path
            before_content = file_at_commit(repo, base_sha, before_path)
            after_content = file_at_commit(repo, tmp_ref, changed_path.path)
            context = DiffContext(
                repo_full_name=repo_full_name_value,
                commit_sha=str((pr.get("head") or {}).get("sha") or tmp_ref),
                parent_sha=base_sha,
                commit_date_utc=pr.get("updated_at") or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                file_path=changed_path.path,
                platform=platform,
                change_source_type="pull_request",
                public_url=pr.get("html_url") or f"https://github.com/{repo_full_name_value}/pull/{number}",
                pr_number=int(number),
                pr_state=_pr_state(pr),
                pr_title=pr.get("title"),
                pr_body_excerpt=_excerpt(pr.get("body")),
                pr_draft=pr.get("draft"),
                contributor_login=(pr.get("user") or {}).get("login"),
                commit_message="Open pull request proposed changes",
                evidence_type=extract_evidence_types(pr.get("body")),
            )
            before_snapshot = parse_matrix_content(before_content, platform=platform, file_path=before_path, config=config)
            after_snapshot = parse_matrix_content(after_content, platform=platform, file_path=changed_path.path, config=config)
            events.extend(diff_snapshots(before_snapshot, after_snapshot, context, scoring, config).events)
        run_git(repo, ["update-ref", "-d", tmp_ref], check=False)
    return events


def _parse_name_status(output: str) -> list[ChangedPath]:
    paths: list[ChangedPath] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith("R") and len(parts) >= 3:
            paths.append(ChangedPath(status=status, old_path=parts[1], path=parts[2]))
        elif len(parts) >= 2:
            paths.append(ChangedPath(status=status, path=parts[1]))
    return paths


def enrich_pr_summary(rows: list[dict[str, Any]], github: dict[str, Any]) -> list[dict[str, Any]]:
    pr_by_number = github.get("pr_by_number") or {}
    rows_by_number = {row["pr_number"]: row for row in rows}
    for row in rows:
        pr = pr_by_number.get(row["pr_number"])
        if not pr:
            continue
        row["state"] = _pr_state(pr)
        row["draft"] = pr.get("draft")
        row["created_at"] = pr.get("created_at")
        row["merged_at"] = pr.get("merged_at")
        row["author"] = (pr.get("user") or {}).get("login")
        row["title"] = pr.get("title")
        row["public_url"] = pr.get("html_url")
    for pr in github.get("prs") or []:
        number = pr.get("number")
        if number is None or number in rows_by_number:
            continue
        files = github.get("files_by_pr", {}).get(int(number), [])
        rows.append(
            {
                "pr_number": int(number),
                "title": pr.get("title"),
                "state": _pr_state(pr),
                "draft": pr.get("draft"),
                "created_at": pr.get("created_at"),
                "merged_at": pr.get("merged_at"),
                "author": (pr.get("user") or {}).get("login"),
                "changed_score_bearing_files": sorted({file_info.get("filename") for file_info in files if score_bearing_platform_for_path(file_info.get("filename") or "")}),
                "changed_telemetry_cells": 0,
                "score_delta": 0.0,
                "vendors_affected": [],
                "categories_affected": [],
                "evidence_types": [],
                "maintainer_reviewed": False,
                "public_url": pr.get("html_url"),
            }
        )
    return sorted(rows, key=lambda row: row["pr_number"])


def schema_document() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "files": {
            "telemetry_change_events.jsonl": "One changed telemetry cell per line with score delta, quality delta, provenance, and classification.",
            "telemetry_change_events.csv": "CSV projection of the event ledger when --format includes csv.",
            "current_vendor_scores.json": "Current weighted score per vendor and platform using Tools/compare.py.",
            "vendor_score_timeseries.json": "Cumulative score points by vendor/platform over accepted history.",
            "vendor_change_summary.json": "Vendor-level counts and score deltas.",
            "category_change_summary.json": "Category/sub-category improvement counts and affected vendors/platforms.",
            "contributor_summary.json": "Contributor-class activity and score delta summary.",
            "pr_summary.json": "Pull-request-level accepted telemetry change summary.",
            "direct_commit_summary.json": "Direct commit summary for commits not associated with a PR.",
            "open_pr_proposed_changes.json": "Open pull request proposed cell changes, excluded from accepted statistics.",
            "manual_review_items.json": "Warnings and ambiguous changes requiring human review.",
            "run_metadata.json": "Generation run metadata, counts, versioning, and warnings.",
            "data/raw/github/pr_commits.jsonl": "Raw PR commit metadata cache used for commit-to-PR association when GitHub API enrichment is available.",
        },
    }


def _manual_review_warning_summaries(items: list[dict[str, Any]], per_kind_limit: int = 20) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    counts_by_kind: dict[str, int] = {}
    for item in items:
        event = item.get("event") or {}
        kind = item.get("reason") or item.get("kind") or "manual_review"
        counts_by_kind[kind] = counts_by_kind.get(kind, 0) + 1
        if counts_by_kind[kind] > per_kind_limit:
            continue
        summary = {
            "kind": kind,
            "message": item.get("message") or "Manual review item generated.",
        }
        for key in ["commit_sha", "file_path", "platform", "vendor", "status"]:
            if item.get(key) is not None:
                summary[key] = item[key]
        for key in ["commit_sha", "file_path", "platform", "vendor_canonical_id", "sub_category", "change_kind"]:
            if event.get(key) is not None:
                summary[key] = event[key]
        summaries.append(summary)
    for kind, count in sorted(counts_by_kind.items()):
        if count > per_kind_limit:
            summaries.append({"kind": f"{kind}_truncated", "message": f"{count - per_kind_limit} additional {kind} warnings omitted from run_metadata; see manual_review_items.json."})
    return summaries


def _change_source_type(message: str, pr_number: int | None) -> str:
    if "Merge pull request #" in (message or ""):
        return "merge_commit"
    if pr_number is not None:
        return "pull_request"
    return "direct_commit"


def _contributor_login(metadata: dict[str, Any], pr: dict[str, Any] | None) -> str | None:
    if pr and pr.get("user"):
        return pr["user"].get("login")
    email = metadata.get("author_email") or ""
    if "users.noreply.github.com" in email:
        local = email.split("@", 1)[0]
        if "+" in local:
            return local.split("+", 1)[1]
        return local
    return None


def _public_url(repo_full_name_value: str, sha: str, pr_number: int | None) -> str:
    if pr_number:
        return f"https://github.com/{repo_full_name_value}/pull/{pr_number}"
    return f"https://github.com/{repo_full_name_value}/commit/{sha}"


def _pr_state(pr: dict[str, Any] | None) -> str | None:
    if not pr:
        return None
    if pr.get("draft"):
        return "draft"
    if pr.get("merged_at"):
        return "merged"
    return pr.get("state")


def _excerpt(text: str | None, limit: int = 500) -> str | None:
    if not text:
        return None
    cleaned = " ".join(text.split())
    return cleaned[:limit]


def _date_in_range(date_value: str, since: str | None, until: str | None) -> bool:
    since_bound = _normalize_date_bound(since, is_end=False)
    until_bound = _normalize_date_bound(until, is_end=True)
    if since_bound and date_value < since_bound:
        return False
    if until_bound and date_value > until_bound:
        return False
    return True


def _normalize_date_bound(value: str | None, *, is_end: bool) -> str | None:
    if not value:
        return None
    if len(value) == 10 and value[4] == "-" and value[7] == "-":
        return f"{value}T23:59:59Z" if is_end else f"{value}T00:00:00Z"
    return value


def _env_pr_number() -> int | None:
    payload = _github_event_payload()
    if payload:
        try:
            return int(payload.get("pull_request", {}).get("number"))
        except Exception:
            return None
    return None


def _github_event_payload() -> dict[str, Any]:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).exists():
        try:
            return json.loads(Path(event_path).read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_event_csv(path: Path, events: list[dict[str, Any]]) -> None:
    fields = [
        "change_event_id",
        "commit_sha",
        "commit_date_utc",
        "change_source_type",
        "pr_number",
        "platform",
        "file_path",
        "vendor_canonical_id",
        "vendor_display_name",
        "telemetry_feature_category",
        "sub_category",
        "old_status",
        "new_status",
        "old_status_score",
        "new_status_score",
        "sub_category_weight",
        "weighted_score_delta",
        "status_quality_delta",
        "direction",
        "change_kind",
        "contributor_login",
        "contributor_class",
        "public_url",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)


if __name__ == "__main__":
    raise SystemExit(main())
