from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .git_history import write_jsonl


def collect_github_metadata(repo_full_name: str, raw_output: Path, token_env: str = "GITHUB_TOKEN", *, refresh: bool = False) -> dict[str, Any]:
    token = os.environ.get(token_env)
    raw_output.mkdir(parents=True, exist_ok=True)
    if not token:
        _ensure_empty_raw_files(raw_output)
        return {
            "prs": [],
            "pr_by_number": {},
            "reviews_by_pr": {},
            "comments_by_pr": {},
            "files_by_pr": {},
            "commit_pr_map": {},
            "warnings": [{"kind": "github_token_missing", "message": f"{token_env} is not set; PR API enrichment was skipped."}],
        }
    warnings: list[dict[str, Any]] = []
    cached = _load_cached(raw_output)
    if cached["prs"] and not refresh:
        return _incrementally_refresh_cached_metadata(repo_full_name, raw_output, token, cached, warnings)

    prs = _request_paginated(f"https://api.github.com/repos/{repo_full_name}/pulls?state=all&per_page=100", token, warnings)
    reviews: list[dict[str, Any]] = []
    comments: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    pr_commits: list[dict[str, Any]] = []
    for pr in prs:
        number = pr["number"]
        reviews.extend(_request_paginated(f"https://api.github.com/repos/{repo_full_name}/pulls/{number}/reviews?per_page=100", token, warnings))
        comments.extend(_request_paginated(f"https://api.github.com/repos/{repo_full_name}/issues/{number}/comments?per_page=100", token, warnings))
        for file_info in _request_paginated(f"https://api.github.com/repos/{repo_full_name}/pulls/{number}/files?per_page=100", token, warnings):
            file_info["pr_number"] = number
            files.append(file_info)
        for commit_info in _request_paginated(f"https://api.github.com/repos/{repo_full_name}/pulls/{number}/commits?per_page=100", token, warnings):
            commit_info["pr_number"] = number
            pr_commits.append(commit_info)

    write_jsonl(raw_output / "prs.jsonl", prs)
    write_jsonl(raw_output / "pr_reviews.jsonl", reviews)
    write_jsonl(raw_output / "pr_comments.jsonl", comments)
    write_jsonl(raw_output / "pr_files.jsonl", files)
    write_jsonl(raw_output / "pr_commits.jsonl", pr_commits)

    return _build_metadata(prs, reviews, comments, files, pr_commits, warnings)


def _incrementally_refresh_cached_metadata(
    repo_full_name: str,
    raw_output: Path,
    token: str,
    cached: dict[str, Any],
    warnings: list[dict[str, Any]],
) -> dict[str, Any]:
    cached_prs = cached.get("prs") or []
    cutoff = max((pr.get("updated_at") or "" for pr in cached_prs), default="")
    updated_prs = _request_paginated_until(
        f"https://api.github.com/repos/{repo_full_name}/pulls?state=all&sort=updated&direction=desc&per_page=100",
        token,
        warnings,
        cutoff,
    )
    if not updated_prs:
        cached.setdefault("warnings", []).append({"kind": "github_cache_reused", "message": "Reused existing raw GitHub API cache files."})
        return cached

    updated_numbers = {int(pr["number"]) for pr in updated_prs if pr.get("number") is not None}
    prs_by_number = {int(pr["number"]): pr for pr in cached_prs if pr.get("number") is not None}
    for pr in updated_prs:
        if pr.get("number") is not None:
            prs_by_number[int(pr["number"])] = pr

    reviews = _rows_excluding_prs(_read_jsonl(raw_output / "pr_reviews.jsonl"), updated_numbers)
    comments = _rows_excluding_prs(_read_jsonl(raw_output / "pr_comments.jsonl"), updated_numbers)
    files = [row for row in _read_jsonl(raw_output / "pr_files.jsonl") if int(row.get("pr_number") or 0) not in updated_numbers]
    pr_commits = [row for row in _read_jsonl(raw_output / "pr_commits.jsonl") if int(row.get("pr_number") or 0) not in updated_numbers]

    for number in sorted(updated_numbers):
        reviews.extend(_request_paginated(f"https://api.github.com/repos/{repo_full_name}/pulls/{number}/reviews?per_page=100", token, warnings))
        comments.extend(_request_paginated(f"https://api.github.com/repos/{repo_full_name}/issues/{number}/comments?per_page=100", token, warnings))
        for file_info in _request_paginated(f"https://api.github.com/repos/{repo_full_name}/pulls/{number}/files?per_page=100", token, warnings):
            file_info["pr_number"] = number
            files.append(file_info)
        for commit_info in _request_paginated(f"https://api.github.com/repos/{repo_full_name}/pulls/{number}/commits?per_page=100", token, warnings):
            commit_info["pr_number"] = number
            pr_commits.append(commit_info)

    prs = sorted(prs_by_number.values(), key=lambda pr: int(pr.get("number") or 0))
    write_jsonl(raw_output / "prs.jsonl", prs)
    write_jsonl(raw_output / "pr_reviews.jsonl", reviews)
    write_jsonl(raw_output / "pr_comments.jsonl", comments)
    write_jsonl(raw_output / "pr_files.jsonl", files)
    write_jsonl(raw_output / "pr_commits.jsonl", pr_commits)
    warnings.append({"kind": "github_cache_incremental_refresh", "message": f"Refreshed GitHub API cache for {len(updated_numbers)} updated pull request(s)."})
    return _build_metadata(prs, reviews, comments, files, pr_commits, warnings)


def _build_metadata(
    prs: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    comments: list[dict[str, Any]],
    files: list[dict[str, Any]],
    pr_commits: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> dict[str, Any]:
    reviews_by_pr: dict[int, list[dict[str, Any]]] = {}
    for review in reviews:
        reviews_by_pr.setdefault(int(review.get("pull_request_url", "").rstrip("/").split("/")[-1] or 0), []).append(review)
    comments_by_pr: dict[int, list[dict[str, Any]]] = {}
    for comment in comments:
        pr_number = int(comment.get("issue_url", "").rstrip("/").split("/")[-1] or 0)
        comments_by_pr.setdefault(pr_number, []).append(comment)
    files_by_pr: dict[int, list[dict[str, Any]]] = {}
    for file_info in files:
        pr_number = int(file_info.get("pr_number") or 0)
        files_by_pr.setdefault(pr_number, []).append(file_info)

    return {
        "prs": prs,
        "pr_by_number": {int(pr["number"]): pr for pr in prs},
        "reviews_by_pr": reviews_by_pr,
        "comments_by_pr": comments_by_pr,
        "files_by_pr": files_by_pr,
        "commit_pr_map": build_pr_commit_map(pr_commits),
        "warnings": warnings,
    }


def _rows_excluding_prs(rows: list[dict[str, Any]], pr_numbers: set[int]) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for row in rows:
        url = row.get("pull_request_url") or row.get("issue_url") or ""
        pr_number = int(str(url).rstrip("/").split("/")[-1] or 0)
        if pr_number not in pr_numbers:
            filtered.append(row)
    return filtered


def _ensure_empty_raw_files(raw_output: Path) -> None:
    for file_name in ["prs.jsonl", "pr_comments.jsonl", "pr_reviews.jsonl", "pr_files.jsonl", "pr_commits.jsonl"]:
        path = raw_output / file_name
        if not path.exists():
            write_jsonl(path, [])


def _load_cached(raw_output: Path) -> dict[str, Any]:
    prs = _read_jsonl(raw_output / "prs.jsonl")
    reviews = _read_jsonl(raw_output / "pr_reviews.jsonl")
    comments = _read_jsonl(raw_output / "pr_comments.jsonl")
    files = _read_jsonl(raw_output / "pr_files.jsonl")
    pr_commits = _read_jsonl(raw_output / "pr_commits.jsonl")

    reviews_by_pr: dict[int, list[dict[str, Any]]] = {}
    for review in reviews:
        pr_number = int(review.get("pull_request_url", "").rstrip("/").split("/")[-1] or 0)
        reviews_by_pr.setdefault(pr_number, []).append(review)
    comments_by_pr: dict[int, list[dict[str, Any]]] = {}
    for comment in comments:
        pr_number = int(comment.get("issue_url", "").rstrip("/").split("/")[-1] or 0)
        comments_by_pr.setdefault(pr_number, []).append(comment)
    files_by_pr: dict[int, list[dict[str, Any]]] = {}
    for file_info in files:
        pr_number = int(file_info.get("pr_number") or 0)
        files_by_pr.setdefault(pr_number, []).append(file_info)

    return {
        "prs": prs,
        "pr_by_number": {int(pr["number"]): pr for pr in prs if pr.get("number") is not None},
        "reviews_by_pr": reviews_by_pr,
        "comments_by_pr": comments_by_pr,
        "files_by_pr": files_by_pr,
        "commit_pr_map": build_pr_commit_map(pr_commits),
        "warnings": [],
    }


def build_pr_commit_map(pr_commits: list[dict[str, Any]]) -> dict[str, int]:
    mapping: dict[str, int] = {}
    for row in pr_commits:
        sha = row.get("sha")
        pr_number = row.get("pr_number")
        if sha and pr_number is not None:
            mapping[str(sha)] = int(pr_number)
    return mapping


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _request_paginated(url: str, token: str, warnings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    next_url: str | None = url
    while next_url:
        request = urllib.request.Request(
            next_url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "edr-telemetry-stats-generator",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                rows.extend(json.loads(response.read().decode("utf-8")))
                next_url = _next_link(response.headers.get("Link"))
        except urllib.error.HTTPError as exc:
            warnings.append({"kind": "github_api_http_error", "url": url, "status": exc.code, "message": str(exc)})
            break
        except urllib.error.URLError as exc:
            warnings.append({"kind": "github_api_url_error", "url": url, "message": str(exc)})
            break
    return rows


def _request_paginated_until(url: str, token: str, warnings: list[dict[str, Any]], cutoff_updated_at: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    next_url: str | None = url
    while next_url:
        page = _request_page(next_url, token, warnings)
        if page is None:
            break
        page_rows, next_url = page
        rows.extend([row for row in page_rows if (row.get("updated_at") or "") >= cutoff_updated_at])
        if cutoff_updated_at and all((row.get("updated_at") or "") < cutoff_updated_at for row in page_rows):
            break
    return rows


def _request_page(url: str, token: str, warnings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str | None] | None:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "edr-telemetry-stats-generator",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8")), _next_link(response.headers.get("Link"))
    except urllib.error.HTTPError as exc:
        warnings.append({"kind": "github_api_http_error", "url": url, "status": exc.code, "message": str(exc)})
    except urllib.error.URLError as exc:
        warnings.append({"kind": "github_api_url_error", "url": url, "message": str(exc)})
    return None


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        section, _, rel = part.partition(";")
        if 'rel="next"' in rel:
            return section.strip()[1:-1]
    return None
