from pathlib import Path

from telemetry_stats.git_history import (
    default_branch,
    extract_pr_number_from_commit_message,
    run_git,
    score_bearing_platform_for_path,
)
from telemetry_stats.github_api import build_pr_commit_map, collect_github_metadata


def _init_test_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, ["init", "-b", "main"])
    (repo / "README.md").write_text("test", encoding="utf-8")
    run_git(repo, ["add", "."])
    run_git(repo, ["config", "user.email", "test@example.com"])
    run_git(repo, ["config", "user.name", "Test User"])
    run_git(repo, ["commit", "-m", "init"])
    return repo


def test_default_branch_returns_current_branch_when_attached(tmp_path):
    repo = _init_test_repo(tmp_path)

    assert default_branch(repo) == "main"


def test_default_branch_resolves_origin_head_when_detached(tmp_path):
    repo = _init_test_repo(tmp_path)
    run_git(repo, ["config", "remote.origin.url", "https://github.com/example/example.git"])
    run_git(repo, ["update-ref", "refs/remotes/origin/main", "HEAD"])
    run_git(repo, ["symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"])
    run_git(repo, ["checkout", "--detach"])
    run_git(repo, ["branch", "-D", "main"])

    assert default_branch(repo) == "origin/main"


def test_default_branch_falls_back_to_head_when_no_refs_resolve(tmp_path):
    repo = _init_test_repo(tmp_path)
    run_git(repo, ["checkout", "--detach"])
    run_git(repo, ["branch", "-D", "main"])

    assert default_branch(repo) == "HEAD"


def test_associates_pr_from_squash_commit_message():
    assert extract_pr_number_from_commit_message("Adding additional scoring to Elastic (#204)") == 204


def test_associates_pr_from_merge_commit_message():
    assert extract_pr_number_from_commit_message("Merge pull request #123 from branch") == 123


def test_score_bearing_file_platform_detection_includes_legacy_names():
    assert score_bearing_platform_for_path("EDR_telem_windows.json") == "windows"
    assert score_bearing_platform_for_path("EDR_telem.json") == "windows"
    assert score_bearing_platform_for_path("EDR_telem_mac.json") == "macos"
    assert score_bearing_platform_for_path("README.md") is None


def test_builds_commit_to_pr_map_from_api_commit_rows():
    assert build_pr_commit_map(
        [
            {"pr_number": 10, "sha": "aaa"},
            {"pr_number": 11, "sha": "bbb"},
        ]
    ) == {"aaa": 10, "bbb": 11}


def test_missing_github_token_is_reported_in_metadata(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    metadata = collect_github_metadata("tsale/EDR-Telemetry", tmp_path)

    assert metadata["commit_pr_map"] == {}
    assert metadata["warnings"][0]["kind"] == "github_token_missing"
