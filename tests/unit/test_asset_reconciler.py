from __future__ import annotations

import pytest
from asset_reconciler import AssetFragment, build_asset_snapshot_payload, detect_drift, reconcile


def test_reconcile_merges_disjoint_fields():
    frags = [
        AssetFragment(source="netbox", asset_id="a1", fields={"namespace": "argos-cyber-range"}),
        AssetFragment(source="kaudit", asset_id="a1", fields={"workload_id": "deployment/x"}),
    ]
    merged, conflicts = reconcile(frags)
    assert merged == {"namespace": "argos-cyber-range", "workload_id": "deployment/x"}
    assert conflicts == []


def test_reconcile_flags_conflicting_values():
    frags = [
        AssetFragment(source="netbox", asset_id="a1", fields={"namespace": "argos-cyber-range"}),
        AssetFragment(source="kaudit", asset_id="a1", fields={"namespace": "default"}),
    ]
    _, conflicts = reconcile(frags)
    assert len(conflicts) == 1
    assert conflicts[0]["field"] == "namespace"
    assert conflicts[0]["values"] == {"netbox": "argos-cyber-range", "kaudit": "default"}


def test_reconcile_rejects_mixed_asset_ids():
    frags = [
        AssetFragment(source="netbox", asset_id="a1", fields={}),
        AssetFragment(source="kaudit", asset_id="a2", fields={}),
    ]
    with pytest.raises(ValueError):
        reconcile(frags)


def test_build_asset_snapshot_payload_is_schema_valid(contracts_path, context):
    frags = [AssetFragment(source="netbox", asset_id="a1", fields={"namespace": "argos-cyber-range"})]
    result = build_asset_snapshot_payload(contracts_path, context, "a1", frags)
    assert result.payload["asset_id"] == "a1"
    assert result.payload["criticality_esp"] == "medium"  # default conservador


def test_detect_drift_reports_only_differing_fields():
    drift = detect_drift(
        {"namespace": "argos-cyber-range", "node": "node-1"},
        {"namespace": "argos-cyber-range", "node": "node-2"},
    )
    assert drift == [{"field": "node", "as_designed": "node-1", "as_built": "node-2"}]


def test_detect_drift_empty_when_identical():
    snapshot = {"namespace": "x", "node": "y"}
    assert detect_drift(snapshot, dict(snapshot)) == []


# ---------------------------------------------------------------------------
# ADR-061 (Fase K): reconcile() con authority_ranking real -- extiende,
# no duplica, la detección de conflictos ya existente.
# ---------------------------------------------------------------------------


def test_reconcile_without_authority_ranking_keeps_the_original_last_wins_behavior():
    frags = [
        AssetFragment(source="netbox", asset_id="a1", fields={"namespace": "argos-cyber-range"}),
        AssetFragment(source="kaudit", asset_id="a1", fields={"namespace": "default"}),
    ]
    merged, conflicts = reconcile(frags)
    assert merged["namespace"] == "default"  # última fuente, comportamiento sin cambios
    assert "resolution" not in conflicts[0]


def test_reconcile_with_authority_ranking_resolves_by_governed_precedence_not_order():
    frags = [
        AssetFragment(source="netbox", asset_id="a1", fields={"namespace": "argos-cyber-range"}),
        AssetFragment(source="cmam", asset_id="a1", fields={"namespace": "default"}),
    ]
    merged, conflicts = reconcile(frags, authority_ranking={"cmam": 10, "netbox": 1})
    assert merged["namespace"] == "default"  # cmam gana por autoridad, no por ser la última
    assert conflicts[0]["resolution"]["winning_source"] == "cmam"
    assert conflicts[0]["resolution"]["state"] == "CONFLICT"


def test_reconcile_with_authority_ranking_and_unresolvable_tie_omits_the_field():
    frags = [
        AssetFragment(source="cmam-a", asset_id="a1", fields={"namespace": "zone-a"}),
        AssetFragment(source="cmam-b", asset_id="a1", fields={"namespace": "zone-b"}),
    ]
    merged, conflicts = reconcile(frags, authority_ranking={"cmam-a": 10, "cmam-b": 10})
    assert "namespace" not in merged  # nunca se afirma un valor arbitrario sin resolución gobernada
    assert conflicts[0]["resolution"]["state"] == "REQUIRES_AUTHORITY"


def test_build_asset_snapshot_payload_with_authority_ranking(contracts_path, context):
    frags = [
        AssetFragment(source="netbox", asset_id="a1", fields={"criticality_esp": "low"}),
        AssetFragment(source="cmam", asset_id="a1", fields={"criticality_esp": "high"}),
    ]
    result = build_asset_snapshot_payload(contracts_path, context, "a1", frags, authority_ranking={"cmam": 10, "netbox": 1})
    assert result.payload["criticality_esp"] == "high"
    assert result.conflicts[0]["resolution"]["winning_source"] == "cmam"
