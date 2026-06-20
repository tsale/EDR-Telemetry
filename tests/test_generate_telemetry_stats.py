import importlib.util
from pathlib import Path


def _load_generator():
    script = Path(__file__).resolve().parents[1] / "scripts" / "generate_telemetry_stats.py"
    spec = importlib.util.spec_from_file_location("generate_telemetry_stats", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_until_date_includes_the_whole_utc_day():
    module = _load_generator()

    assert module._date_in_range("2026-06-01T23:59:59Z", None, "2026-06-01")
    assert not module._date_in_range("2026-06-02T00:00:00Z", None, "2026-06-01")


def test_enrich_pr_summary_includes_api_prs_without_accepted_events():
    module = _load_generator()

    rows = module.enrich_pr_summary(
        [],
        {
            "prs": [
                {
                    "number": 9,
                    "title": "Proposed telemetry update",
                    "state": "closed",
                    "draft": False,
                    "created_at": "2026-06-01T00:00:00Z",
                    "merged_at": None,
                    "html_url": "https://github.com/tsale/EDR-Telemetry/pull/9",
                    "user": {"login": "alice"},
                }
            ],
            "pr_by_number": {},
            "files_by_pr": {9: [{"filename": "EDR_telem_windows.json"}]},
        },
    )

    assert rows == [
        {
            "pr_number": 9,
            "title": "Proposed telemetry update",
            "state": "closed",
            "draft": False,
            "created_at": "2026-06-01T00:00:00Z",
            "merged_at": None,
            "author": "alice",
            "changed_score_bearing_files": ["EDR_telem_windows.json"],
            "changed_telemetry_cells": 0,
            "score_delta": 0.0,
            "vendors_affected": [],
            "categories_affected": [],
            "evidence_types": [],
            "maintainer_reviewed": False,
            "public_url": "https://github.com/tsale/EDR-Telemetry/pull/9",
        }
    ]


def test_write_event_csv_outputs_requested_event_fields(tmp_path):
    module = _load_generator()
    path = tmp_path / "events.csv"

    module.write_event_csv(
        path,
        [
            {
                "change_event_id": "id1",
                "commit_sha": "abc",
                "platform": "windows",
                "vendor_canonical_id": "elastic",
                "old_status": "No",
                "new_status": "Yes",
                "weighted_score_delta": 1.0,
                "change_kind": "coverage_upgrade",
            }
        ],
    )

    text = path.read_text(encoding="utf-8")
    assert text.startswith("change_event_id,commit_sha,")
    assert "id1,abc,,,,windows" in text
