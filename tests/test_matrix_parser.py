import json

from telemetry_stats.config import StatsConfig
from telemetry_stats.matrix_parser import parse_matrix_content


def test_parses_matrix_and_forward_fills_parent_categories():
    matrix = [
        {
            "Telemetry Feature Category": "Process Activity",
            "Sub-Category": "Process Creation",
            "Elastic": "Yes",
        },
        {
            "Telemetry Feature Category": None,
            "Sub-Category": "Process Termination",
            "Elastic": "No",
        },
    ]

    snapshot = parse_matrix_content(
        json.dumps(matrix),
        platform="windows",
        file_path="EDR_telem_windows.json",
        config=StatsConfig(),
    )

    assert not snapshot.warnings
    assert snapshot.cells[("Process Activity", "Process Creation", "elastic")].status == "Yes"
    assert snapshot.cells[("Process Activity", "Process Termination", "elastic")].status == "No"


def test_unknown_status_is_warned_and_preserved_when_not_strict():
    matrix = [
        {
            "Telemetry Feature Category": "Network Activity",
            "Sub-Category": "DNS Query",
            "Elastic": "Sometimes",
        }
    ]

    snapshot = parse_matrix_content(
        json.dumps(matrix),
        platform="linux",
        file_path="EDR_telem_linux.json",
        config=StatsConfig(),
    )

    assert snapshot.cells[("Network Activity", "DNS Query", "elastic")].status == "Sometimes"
    assert snapshot.warnings
    assert snapshot.warnings[0]["kind"] == "unknown_status"


def test_malformed_json_returns_warning_and_empty_snapshot():
    snapshot = parse_matrix_content(
        "{not-json",
        platform="windows",
        file_path="EDR_telem_windows.json",
        config=StatsConfig(),
    )

    assert snapshot.cells == {}
    assert snapshot.warnings
    assert snapshot.warnings[0]["kind"] == "failed_json_parse"
