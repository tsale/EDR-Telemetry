from telemetry_stats.config import StatsConfig


def test_contributor_classification_is_case_insensitive_for_logins():
    config = StatsConfig.from_dict(
        {
            "maintainers": ["tsale"],
            "vendor_affiliations": {"elastic": {"github_logins": ["elastic-user"]}},
        }
    )

    assert config.contributor_class("Tsale") == "maintainer"
    assert config.contributor_class("Elastic-User") == "vendor"
    assert config.vendor_for_login("Elastic-User") == "elastic"
