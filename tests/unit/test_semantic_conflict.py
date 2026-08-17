from __future__ import annotations

from semantic_conflict import SourceClaim, resolve_conflict


def _claim(source_id, value, observed_at="2026-01-01T00:00:00Z", evidence_ref=None):
    return SourceClaim(source_id=source_id, value=value, observed_at=observed_at, evidence_ref=evidence_ref)


def test_no_claims_is_unknown():
    result = resolve_conflict("asset-x", "criticality", [], classification="CLASSIFICATION")
    assert result.state == "UNKNOWN"
    assert result.reason_code == "NO_CLAIMS"


def test_single_claim_is_consistent():
    result = resolve_conflict("asset-x", "criticality", [_claim("cmam", "high")], classification="CLASSIFICATION")
    assert result.state == "CONSISTENT"
    assert result.winning_source == "cmam"


def test_multiple_claims_agreeing_is_consistent():
    result = resolve_conflict("asset-x", "criticality", [_claim("cmam", "high"), _claim("netbox", "high")], classification="CLASSIFICATION")
    assert result.state == "CONSISTENT"
    assert result.reason_code == "ALL_SOURCES_AGREE"


def test_cmam_vs_legacy_example_resolved_by_governed_authority():
    """El ejemplo literal del prompt: CMAM: HIGH, Legacy: LOW -- con una
    política real (CMAM más autoritativo que Legacy), se resuelve por
    regla determinista, no por "última fuente"."""
    claims = [_claim("cmam", "HIGH"), _claim("legacy", "LOW")]
    result = resolve_conflict("asset-x", "criticality", claims, classification="CLASSIFICATION", authority_ranking={"cmam": 10, "legacy": 1})
    assert result.state == "CONFLICT"
    assert result.winning_source == "cmam"
    assert result.rejected_sources == ("legacy",)
    assert result.rule == "authority_precedence"


def test_conflict_without_authority_ranking_requires_authority():
    """Sin política gobernada, nunca se elige arbitrariamente."""
    claims = [_claim("cmam", "HIGH"), _claim("legacy", "LOW")]
    result = resolve_conflict("asset-x", "criticality", claims, classification="CLASSIFICATION")
    assert result.state == "REQUIRES_AUTHORITY"
    assert result.winning_source is None


def test_conflict_with_a_source_missing_from_the_ranking_requires_authority():
    claims = [_claim("cmam", "HIGH"), _claim("unknown-source", "LOW")]
    result = resolve_conflict("asset-x", "criticality", claims, classification="CLASSIFICATION", authority_ranking={"cmam": 10})
    assert result.state == "REQUIRES_AUTHORITY"
    assert result.reason_code == "NO_GOVERNED_AUTHORITY_FOR_SOURCE"


def test_tied_authority_but_same_value_is_conflict_resolved_by_agreement():
    claims = [_claim("cmam-a", "HIGH"), _claim("cmam-b", "HIGH"), _claim("legacy", "LOW")]
    result = resolve_conflict(
        "asset-x", "criticality", claims, classification="CLASSIFICATION",
        authority_ranking={"cmam-a": 10, "cmam-b": 10, "legacy": 1},
    )
    assert result.state == "CONFLICT"
    assert result.winning_source in ("cmam-a", "cmam-b")
    assert "legacy" in result.rejected_sources


def test_tied_authority_different_values_breaks_tie_by_freshness():
    claims = [
        _claim("cmam-a", "HIGH", observed_at="2026-01-01T00:00:00Z"),
        _claim("cmam-b", "MEDIUM", observed_at="2026-06-01T00:00:00Z"),  # más reciente
    ]
    result = resolve_conflict(
        "asset-x", "criticality", claims, classification="CLASSIFICATION",
        authority_ranking={"cmam-a": 10, "cmam-b": 10},
    )
    assert result.state == "CONFLICT"
    assert result.winning_source == "cmam-b"
    assert result.rule == "authority_precedence+freshness_tiebreak"


def test_tied_authority_and_tied_freshness_requires_authority():
    claims = [
        _claim("cmam-a", "HIGH", observed_at="2026-01-01T00:00:00Z"),
        _claim("cmam-b", "MEDIUM", observed_at="2026-01-01T00:00:00Z"),
    ]
    result = resolve_conflict(
        "asset-x", "criticality", claims, classification="CLASSIFICATION",
        authority_ranking={"cmam-a": 10, "cmam-b": 10},
    )
    assert result.state == "REQUIRES_AUTHORITY"
    assert result.reason_code == "TIED_AUTHORITY_AND_FRESHNESS"


def test_lower_authority_sources_are_always_rejected_not_silently_dropped():
    claims = [_claim("cmam", "HIGH"), _claim("legacy", "LOW"), _claim("spreadsheet", "MEDIUM")]
    result = resolve_conflict(
        "asset-x", "criticality", claims, classification="CLASSIFICATION",
        authority_ranking={"cmam": 10, "legacy": 5, "spreadsheet": 1},
    )
    assert result.winning_source == "cmam"
    assert set(result.rejected_sources) == {"legacy", "spreadsheet"}


def test_evidence_refs_are_preserved_from_all_claims():
    claims = [_claim("cmam", "HIGH", evidence_ref="ev-1"), _claim("legacy", "LOW", evidence_ref="ev-2")]
    result = resolve_conflict("asset-x", "criticality", claims, classification="CLASSIFICATION", authority_ranking={"cmam": 10, "legacy": 1})
    assert set(result.evidence_refs) == {"ev-1", "ev-2"}


def test_classification_is_passed_through_verbatim_not_inferred():
    for classification in ("TEMPORAL", "AUTHORITY", "SEMANTIC", "CLASSIFICATION", "IDENTITY"):
        result = resolve_conflict("asset-x", "attr", [_claim("s", "v")], classification=classification)
        assert result.classification == classification
