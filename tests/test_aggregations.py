from telemetry_stats.aggregations import contributor_summary


def test_contributor_summary_counts_api_prs_even_without_cell_events():
    rows = contributor_summary(
        [],
        prs=[
            {
                "number": 1,
                "state": "open",
                "merged_at": None,
                "user": {"login": "alice"},
            },
            {
                "number": 2,
                "state": "closed",
                "merged_at": "2026-06-01T00:00:00Z",
                "user": {"login": "alice"},
            },
        ],
    )

    assert rows[0]["contributor_login"] == "alice"
    assert rows[0]["prs_opened"] == 2
    assert rows[0]["merged_prs"] == 1
