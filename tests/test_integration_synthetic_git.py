import json
import subprocess
import sys
from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", message)


def _write_matrix(repo: Path, rows):
    (repo / "EDR_telem_windows.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")


def test_cli_walks_synthetic_git_history_and_generates_cell_events(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")

    (repo / "Tools").mkdir()
    (repo / "Tools" / "compare.py").write_text(
        """
FEATURES_DICT_VALUED = {"Yes": 1, "No": 0, "Partially": 0.5, "Via EventLogs": 0.5, "Via EnablingTelemetry": 1, "Pending Response": 0}
WINDOWS_CATEGORIES_VALUED = {"Process Creation": 1, "Process Termination": 0.5}
LINUX_CATEGORIES_VALUED = {}
MACOS_CATEGORIES_VALUED = {}
""",
        encoding="utf-8",
    )
    _write_matrix(
        repo,
        [
            {
                "Telemetry Feature Category": "Process Activity",
                "Sub-Category": "Process Creation",
                "Elastic": "No",
            }
        ],
    )
    _commit(repo, "initial matrix")

    _write_matrix(
        repo,
        [
            {
                "Telemetry Feature Category": "Process Activity",
                "Sub-Category": "Process Creation",
                "Elastic": "Yes",
            }
        ],
    )
    _commit(repo, "Elastic Process Creation update (#7)")

    (repo / "README.md").write_text("Documentation only\n", encoding="utf-8")
    _commit(repo, "Docs update")

    (repo / "config").mkdir()
    (repo / "config" / "stats_config.yml").write_text(
        """
vendor_aliases:
  elastic:
    display_name: Elastic
    aliases:
      - Elastic
      - Elastic Security
""",
        encoding="utf-8",
    )
    _write_matrix(
        repo,
        [
            {
                "Telemetry Feature Category": "Process Activity",
                "Sub-Category": "Process Creation",
                "Elastic Security": "Yes",
            }
        ],
    )
    _commit(repo, "Rename Elastic vendor column")

    _write_matrix(
        repo,
        [
            {
                "Telemetry Feature Category": "Process Activity",
                "Sub-Category": "Process Creation",
                "Elastic Security": "Yes",
            },
            {
                "Telemetry Feature Category": None,
                "Sub-Category": "Process Termination",
                "Elastic Security": "Yes",
            },
        ],
    )
    _commit(repo, "Add process termination category")

    output = tmp_path / "generated"
    raw_output = tmp_path / "raw"
    script = Path(__file__).resolve().parents[1] / "scripts" / "generate_telemetry_stats.py"

    subprocess.check_call(
        [
            sys.executable,
            str(script),
            "--repo",
            str(repo),
            "--branch",
            "main",
            "--output",
            str(output),
            "--raw-output",
            str(raw_output),
            "--config",
            str(repo / "config" / "stats_config.yml"),
        ]
    )

    events = [
        json.loads(line)
        for line in (output / "telemetry_change_events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    kinds = [event["change_kind"] for event in events]

    assert "coverage_upgrade" in kinds
    assert "rename_only" in kinds
    assert "new_category_baseline" in kinds
    assert all(event["sub_category"] != "README.md" for event in events)

    metadata = json.loads((output / "run_metadata.json").read_text(encoding="utf-8"))
    assert metadata["total_commits_scanned"] == 5
    assert metadata["new_commits_scanned"] == 5
    assert metadata["generation_mode"] == "full_rebuild"
    assert metadata["total_change_events"] == len(events)
    assert (raw_output / "commits.jsonl").exists()

    _write_matrix(
        repo,
        [
            {
                "Telemetry Feature Category": "Process Activity",
                "Sub-Category": "Process Creation",
                "Elastic Security": "Yes",
            },
            {
                "Telemetry Feature Category": None,
                "Sub-Category": "Process Termination",
                "Elastic Security": "No",
            },
        ],
    )
    _commit(repo, "Correct process termination coverage")

    subprocess.check_call(
        [
            sys.executable,
            str(script),
            "--repo",
            str(repo),
            "--branch",
            "main",
            "--output",
            str(output),
            "--raw-output",
            str(raw_output),
            "--config",
            str(repo / "config" / "stats_config.yml"),
            "--incremental",
        ]
    )

    incremental_events = [
        json.loads(line)
        for line in (output / "telemetry_change_events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    incremental_metadata = json.loads((output / "run_metadata.json").read_text(encoding="utf-8"))

    assert len(incremental_events) == len(events) + 1
    assert incremental_events[-1]["change_kind"] == "coverage_downgrade"
    assert incremental_metadata["generation_mode"] == "incremental"
    assert incremental_metadata["new_commits_scanned"] == 1
    assert incremental_metadata["total_commits_scanned"] == 6

    full_rebuild_output = tmp_path / "generated_full_rebuild"
    full_rebuild_raw = tmp_path / "raw_full_rebuild"
    subprocess.check_call(
        [
            sys.executable,
            str(script),
            "--repo",
            str(repo),
            "--branch",
            "main",
            "--output",
            str(full_rebuild_output),
            "--raw-output",
            str(full_rebuild_raw),
            "--config",
            str(repo / "config" / "stats_config.yml"),
            "--force-full-rebuild",
        ]
    )

    assert (output / "telemetry_change_events.jsonl").read_text(encoding="utf-8") == (
        full_rebuild_output / "telemetry_change_events.jsonl"
    ).read_text(encoding="utf-8")
    assert json.loads((output / "manual_review_items.json").read_text(encoding="utf-8")) == json.loads(
        (full_rebuild_output / "manual_review_items.json").read_text(encoding="utf-8")
    )
