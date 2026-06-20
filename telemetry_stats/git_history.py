from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCORE_BEARING_FILES = {
    "EDR_telem_windows.json": "windows",
    "EDR_telem.json": "windows",
    "EDR_telem_linux.json": "linux",
    "EDR_telem_macOS.json": "macos",
    "EDR_telem_mac.json": "macos",
}


@dataclass
class ChangedPath:
    status: str
    path: str
    old_path: str | None = None


def run_git(repo: str | Path, args: list[str], *, check: bool = True) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout


def git_command_success(repo: str | Path, args: list[str]) -> bool:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0


def default_branch(repo: str | Path) -> str:
    branch = run_git(repo, ["branch", "--show-current"], check=False).strip()
    return branch or "main"


def list_commits(repo: str | Path, branch: str, *, start_after: str | None = None) -> list[str]:
    revision = f"{start_after}..{branch}" if start_after else branch
    output = run_git(repo, ["rev-list", "--reverse", "--first-parent", revision])
    return [line.strip() for line in output.splitlines() if line.strip()]


def commit_metadata(repo: str | Path, sha: str) -> dict[str, Any]:
    fmt = "%H%x1f%P%x1f%aI%x1f%cI%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B"
    output = run_git(repo, ["show", "-s", f"--format={fmt}", sha])
    parts = output.split("\x1f", 8)
    parents = parts[1].split() if len(parts) > 1 and parts[1] else []
    return {
        "sha": parts[0].strip(),
        "parents": parents,
        "parent_sha": parents[0] if parents else None,
        "author_date": parts[2],
        "committer_date": parts[3],
        "author_name": parts[4],
        "author_email": parts[5],
        "committer_name": parts[6],
        "committer_email": parts[7],
        "message": parts[8].strip() if len(parts) > 8 else "",
    }


def changed_paths_for_commit(repo: str | Path, sha: str, parent_sha: str | None) -> list[ChangedPath]:
    args = ["diff-tree", "--root", "--no-commit-id", "--name-status", "-r", "-M", sha]
    if parent_sha:
        args = ["diff", "--name-status", "-M", parent_sha, sha]
    output = run_git(repo, args)
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


def file_at_commit(repo: str | Path, sha: str | None, path: str | None) -> str | None:
    if not sha or not path:
        return None
    output = run_git(repo, ["show", f"{sha}:{path}"], check=False)
    if output == "" and not path_exists_at_commit(repo, sha, path):
        return None
    return output


def path_exists_at_commit(repo: str | Path, sha: str, path: str) -> bool:
    completed = subprocess.run(
        ["git", "cat-file", "-e", f"{sha}:{path}"],
        cwd=repo,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0


def score_bearing_platform_for_path(path: str) -> str | None:
    return SCORE_BEARING_FILES.get(Path(path).name)


def extract_pr_number_from_commit_message(message: str | None) -> int | None:
    text = message or ""
    match = re.search(r"Merge pull request #(\d+)", text)
    if match:
        return int(match.group(1))
    match = re.search(r"\(#(\d+)\)", text)
    if match:
        return int(match.group(1))
    return None


def repo_full_name(repo: str | Path) -> str:
    env_value = None
    try:
        import os

        env_value = os.environ.get("GITHUB_REPOSITORY")
    except Exception:
        env_value = None
    if env_value:
        return env_value
    remote = run_git(repo, ["remote", "get-url", "origin"], check=False).strip()
    patterns = [
        r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$",
        r"https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, remote)
        if match:
            return f"{match.group('owner')}/{match.group('repo')}"
    return "tsale/EDR-Telemetry"


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
