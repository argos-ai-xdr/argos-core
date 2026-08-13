from __future__ import annotations

from risk_engine import rank_findings, score_finding


def test_kev_and_critical_asset_outranks_fix_available():
    findings = [
        {"finding_id": "f1", "asset_id": "a1", "epss": 0.9, "kev": True, "fix_available": False},
        {"finding_id": "f2", "asset_id": "a1", "epss": 0.9, "kev": False, "fix_available": True},
    ]
    assets = {"a1": {"asset_id": "a1", "criticality_esp": "critical"}}
    ranked = rank_findings(findings, assets)
    assert [r.finding_id for r in ranked] == ["f1", "f2"]


def test_unknown_asset_is_penalized_not_dropped():
    finding = {"finding_id": "f1", "asset_id": "ghost", "epss": 0.5}
    score = score_finding(finding, asset=None)
    assert score.explanation["asset_criticality"] == "unknown"
    assert score.score > 0  # sigue puntuado, no se descarta


def test_explanation_includes_source_ref_for_grounding():
    finding = {"finding_id": "f1", "asset_id": "a1", "epss": 0.5, "source_ref": "snapshots/x.json"}
    score = score_finding(finding, asset=None)
    assert score.explanation["source_ref"] == "snapshots/x.json"


def test_missing_epss_defaults_to_zero_not_crash():
    score = score_finding({"finding_id": "f1", "asset_id": "a1"}, asset=None)
    assert score.score == 0.0
