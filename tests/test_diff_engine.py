import json

import pytest

from telemetry_stats.config import StatsConfig
from telemetry_stats.diff_engine import DiffContext, build_change_event_id, diff_snapshots
from telemetry_stats.matrix_parser import parse_matrix_content
from telemetry_stats.scoring import ScoringModel


def _snapshot(statuses, *, platform="windows", config=None):
    row = {
        "Telemetry Feature Category": "Process Activity",
        "Sub-Category": "Process Creation",
    }
    row.update(statuses)
    return parse_matrix_content(
        json.dumps([row]),
        platform=platform,
        file_path=f"EDR_telem_{platform}.json",
        config=config or StatsConfig(),
    )


def _events(old_status, new_status, *, config=None):
    before = _snapshot({"Elastic": old_status}, config=config)
    after = _snapshot({"Elastic": new_status}, config=config)
    result = diff_snapshots(before, after, _context(), _scoring(), config or StatsConfig())
    return result.events


def _context():
    return DiffContext(
        repo_full_name="tsale/EDR-Telemetry",
        commit_sha="abc123",
        parent_sha="parent123",
        commit_date_utc="2026-06-18T00:00:00Z",
        file_path="EDR_telem_windows.json",
        platform="windows",
        change_source_type="direct_commit",
        public_url="https://github.com/tsale/EDR-Telemetry/commit/abc123",
    )


def _scoring():
    return ScoringModel(
        status_scores={"Yes": 1.0, "No": 0.0, "Partially": 0.5, "Via EventLogs": 0.5, "Via EnablingTelemetry": 1.0, "Pending Response": 0.0},
        weights_by_platform={
            "windows": {"Process Creation": 1.0, "Process Termination": 0.5},
            "linux": {},
            "macos": {},
        },
    )


@pytest.mark.parametrize(
    ("old_status", "new_status", "delta", "kind", "direction"),
    [
        ("No", "Yes", 1.0, "coverage_upgrade", "improved"),
        ("No", "Partially", 0.5, "coverage_upgrade", "improved"),
        ("Partially", "Yes", 0.5, "coverage_upgrade", "improved"),
        ("Via EventLogs", "Yes", 0.5, "coverage_upgrade", "improved"),
        ("Yes", "No", -1.0, "coverage_downgrade", "reduced"),
    ],
)
def test_score_bearing_status_changes_are_classified(old_status, new_status, delta, kind, direction):
    event = _events(old_status, new_status)[0]

    assert event["weighted_score_delta"] == delta
    assert event["change_kind"] == kind
    assert event["direction"] == direction


def test_enabling_telemetry_to_yes_is_quality_improvement_without_score_delta():
    event = _events("Via EnablingTelemetry", "Yes")[0]

    assert event["weighted_score_delta"] == 0.0
    assert event["status_quality_delta"] == 1
    assert event["direction"] == "neutral"
    assert event["change_kind"] == "default_availability_improvement"


def test_new_vendor_column_is_baseline_not_improvement():
    before = parse_matrix_content(
        json.dumps(
            [
                {
                    "Telemetry Feature Category": "Process Activity",
                    "Sub-Category": "Process Creation",
                    "Elastic": "No",
                }
            ]
        ),
        platform="windows",
        file_path="EDR_telem_windows.json",
        config=StatsConfig(),
    )
    after = parse_matrix_content(
        json.dumps(
            [
                {
                    "Telemetry Feature Category": "Process Activity",
                    "Sub-Category": "Process Creation",
                    "Elastic": "No",
                    "SentinelOne": "Yes",
                }
            ]
        ),
        platform="windows",
        file_path="EDR_telem_windows.json",
        config=StatsConfig(),
    )

    result = diff_snapshots(before, after, _context(), _scoring(), StatsConfig())

    assert len(result.events) == 1
    assert result.events[0]["change_kind"] == "new_vendor_baseline"
    assert result.events[0]["weighted_score_delta"] == 0.0


def test_new_subcategory_row_is_taxonomy_baseline_not_improvement():
    before = _snapshot({"Elastic": "No"})
    after = parse_matrix_content(
        json.dumps(
            [
                {
                    "Telemetry Feature Category": "Process Activity",
                    "Sub-Category": "Process Creation",
                    "Elastic": "No",
                },
                {
                    "Telemetry Feature Category": None,
                    "Sub-Category": "Process Termination",
                    "Elastic": "Yes",
                },
            ]
        ),
        platform="windows",
        file_path="EDR_telem_windows.json",
        config=StatsConfig(),
    )

    result = diff_snapshots(before, after, _context(), _scoring(), StatsConfig())

    assert len(result.events) == 1
    assert result.events[0]["change_kind"] == "new_category_baseline"
    assert result.events[0]["weighted_score_delta"] == 0.0


def test_vendor_rename_using_aliases_is_rename_only():
    config = StatsConfig.from_dict(
        {
            "vendor_aliases": {
                "trend_micro_trendai": {
                    "display_name": "Trend Micro / TrendAI",
                    "aliases": ["Trend Micro", "TrendAI"],
                }
            }
        }
    )
    before = _snapshot({"Trend Micro": "Yes"}, config=config)
    after = _snapshot({"TrendAI": "Yes"}, config=config)

    result = diff_snapshots(before, after, _context(), _scoring(), config)

    assert len(result.events) == 1
    assert result.events[0]["change_kind"] == "rename_only"
    assert result.events[0]["vendor_before"] == "Trend Micro"
    assert result.events[0]["vendor_after"] == "TrendAI"
    assert result.events[0]["weighted_score_delta"] == 0.0


def test_unaliased_identical_vendor_column_swap_is_single_rename_event():
    before = _snapshot({"Old Vendor": "Yes"})
    after = _snapshot({"New Vendor": "Yes"})

    result = diff_snapshots(before, after, _context(), _scoring(), StatsConfig())

    assert len(result.events) == 1
    assert result.events[0]["change_kind"] == "rename_only"
    assert result.events[0]["vendor_before"] == "Old Vendor"
    assert result.events[0]["vendor_after"] == "New Vendor"
    assert result.manual_review_items == []


def test_pr_body_vendor_affiliation_claim_marks_matching_vendor_event():
    before = _snapshot({"Elastic": "No"})
    after = _snapshot({"Elastic": "Yes"})
    context = _context()
    context.contributor_login = "elastic-user"
    context.pr_body_excerpt = "I work for Elastic and am submitting the updated telemetry evidence."

    result = diff_snapshots(before, after, context, _scoring(), StatsConfig())

    assert result.events[0]["contributor_class"] == "vendor"
    assert result.events[0]["vendor_affiliation_claimed"] is True
    assert result.events[0]["vendor_affiliation_confidence"] == "medium"


def test_change_event_id_is_deterministic():
    event = {
        "repo_full_name": "tsale/EDR-Telemetry",
        "commit_sha": "abc123",
        "platform": "windows",
        "file_path": "EDR_telem_windows.json",
        "vendor_before": "Elastic",
        "vendor_after": "Elastic",
        "telemetry_feature_category": "Process Activity",
        "sub_category": "Process Creation",
        "old_status": "No",
        "new_status": "Yes",
    }

    assert build_change_event_id(event) == build_change_event_id(dict(reversed(list(event.items()))))
