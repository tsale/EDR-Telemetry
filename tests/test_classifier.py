from telemetry_stats.classifier import classify_non_score_change, extract_evidence_types


def test_documentation_only_changes_do_not_count_as_score_changes():
    assert classify_non_score_change(["README.md", "docs/stats.md"]) == "documentation_only"


def test_tooling_only_changes_do_not_count_as_score_changes():
    assert classify_non_score_change(["Tools/compare.py", ".github/workflows/test.yml"]) == "tooling_only"


def test_extracts_conservative_evidence_types_from_text():
    evidence = extract_evidence_types(
        """
        - [x] Official documentation: https://example.com/docs
        Screenshot: ![proof](https://github.com/user-attachments/assets/abc)
        Tested with the telemetry generator and included event.action samples.
        """
    )

    assert evidence == [
        "official_documentation",
        "screenshots",
        "sanitized_logs",
        "telemetry_generator",
    ]


def test_generic_docs_word_does_not_claim_official_documentation():
    assert extract_evidence_types("Updated the docs and wording.") == ["unknown"]
