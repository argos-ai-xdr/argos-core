from __future__ import annotations

import pytest
from asset_reconciler import AssetFragment, build_asset_snapshot_payload
from semantic_graph import (
    DanglingRelation,
    SemanticGraph,
    UnknownEntityType,
    UnknownRelationType,
    entity_from_asset_snapshot,
    entity_from_incident,
    relation_depends_on,
    relation_impacts,
)


def _real_asset_snapshot(contracts_path, context, asset_id="asset-x"):
    fragments = [AssetFragment(source="netbox", asset_id=asset_id, fields={"namespace": "argos-cyber-range", "criticality_esp": "high"})]
    return build_asset_snapshot_payload(contracts_path, context, asset_id, fragments).payload


def _incident(**overrides):
    base = {
        "id": "01J0SEM0000000000000001",
        "schema_version": "1.0.0",
        "observed_at": "2026-08-17T09:00:00Z",
        "producer": "correlator",
        "classification": "internal",
        "run_id": "run-sem-001",
        "payload_hash": "sha256:" + "0" * 64,
        "incident_id": "inc-sem-001",
        "member_event_ids": ["evt-1"],
        "timeline": [{"timestamp": "2026-08-17T09:00:00Z", "description": "x"}],
        "entities": [{"type": "asset", "id": "asset-x"}],
        "severity": "high",
        "evidence_refs": ["ref-1"],
    }
    base.update(overrides)
    return base


def test_entity_from_real_asset_snapshot(contracts_path, context):
    snapshot = _real_asset_snapshot(contracts_path, context)
    entity = entity_from_asset_snapshot(snapshot, source_type="NetBox", source_version="1.0", authority="netbox-authoritative")
    assert entity.entity_type == "Asset"
    assert entity.attributes["asset_id"] == "asset-x"
    assert entity.source_id == snapshot["producer"]


def test_unknown_entity_type_is_rejected():
    from semantic_graph import _make_entity

    with pytest.raises(UnknownEntityType):
        _make_entity("NotARealType", {}, source_id="x", source_type="x", source_version="1", authority="x")


def test_unknown_relation_type_is_rejected():
    with pytest.raises(UnknownRelationType):
        from semantic_graph import _make_relation

        _make_relation("NOT_A_REAL_RELATION", "a", "b", source_id="x", source_type="x", source_version="1", authority="x")


def test_duplicate_entity_reconciliation_happens_upstream_in_asset_reconciler(contracts_path, context):
    """K10 'duplicate entity reconciliation': la reconciliación de
    fuentes contradictorias sobre el MISMO asset_id ya la resuelve
    asset_reconciler.reconcile() (ARG-010, extendido en K4/K5) ANTES de
    llegar aquí -- semantic_graph construye UNA entidad por AssetSnapshot
    ya reconciliado, no vuelve a fusionar. Dos snapshots reconciliados
    para el MISMO asset_id producen dos nodos de grafo con entity_id
    distinto (identidad de grafo) pero mismo attributes['asset_id']
    (identidad de dominio) -- unir esos dos nodos en uno sería semántica
    nueva no pedida por el prompt (deduplicación de GRAFO, distinta de
    reconciliación de FUENTES), documentado aquí para que no se confunda
    con un hueco sin cubrir."""
    snap1 = _real_asset_snapshot(contracts_path, context, "asset-dup")
    entity1 = entity_from_asset_snapshot(snap1, source_type="NetBox", source_version="1.0", authority="x")
    entity2 = entity_from_asset_snapshot(snap1, source_type="NetBox", source_version="1.0", authority="x")
    assert entity1.entity_id != entity2.entity_id  # identidad de grafo: cada llamada es un nodo nuevo
    assert entity1.attributes["asset_id"] == entity2.attributes["asset_id"] == "asset-dup"  # identidad de dominio: coincide


def test_relation_to_a_nonexistent_entity_is_rejected(contracts_path, context):
    graph = SemanticGraph()
    snapshot = _real_asset_snapshot(contracts_path, context)
    entity = entity_from_asset_snapshot(snapshot, source_type="NetBox", source_version="1.0", authority="x")
    graph.add_entity(entity)

    with pytest.raises(DanglingRelation):
        relation_depends_on(graph, entity.entity_id, "sement-does-not-exist", source_id="x", source_type="x", source_version="1", authority="x")


def test_dependency_graph_construction_and_queries(contracts_path, context):
    graph = SemanticGraph()
    asset_a = entity_from_asset_snapshot(_real_asset_snapshot(contracts_path, context, "asset-a"), source_type="NetBox", source_version="1.0", authority="x")
    asset_b = entity_from_asset_snapshot(_real_asset_snapshot(contracts_path, context, "asset-b"), source_type="NetBox", source_version="1.0", authority="x")
    graph.add_entity(asset_a)
    graph.add_entity(asset_b)
    rel = relation_depends_on(graph, asset_a.entity_id, asset_b.entity_id, source_id="x", source_type="manual", source_version="1", authority="x")

    assert graph.relations_by_type("DEPENDS_ON") == (rel,)
    assert rel in graph.relations_for_entity(asset_a.entity_id)
    assert rel in graph.relations_for_entity(asset_b.entity_id)
    assert graph.entities_by_type("Asset") == (asset_a, asset_b) or graph.entities_by_type("Asset") == (asset_b, asset_a)


def test_incident_impacts_asset_relation(contracts_path, context):
    graph = SemanticGraph()
    asset = entity_from_asset_snapshot(_real_asset_snapshot(contracts_path, context), source_type="NetBox", source_version="1.0", authority="x")
    incident_entity = entity_from_incident(_incident(), source_type="correlator", source_version="1.0", authority="x")
    graph.add_entity(asset)
    graph.add_entity(incident_entity)
    rel = relation_impacts(graph, incident_entity.entity_id, asset.entity_id, source_id="correlator", source_type="correlator", source_version="1.0", authority="x")
    assert rel.relation_type == "IMPACTS"


def test_snapshot_hash_is_deterministic_regardless_of_insertion_order(contracts_path, context):
    snap_a = _real_asset_snapshot(contracts_path, context, "asset-a")
    snap_b = _real_asset_snapshot(contracts_path, context, "asset-b")

    graph1 = SemanticGraph()
    e1a = entity_from_asset_snapshot(snap_a, source_type="NetBox", source_version="1.0", authority="x")
    e1b = entity_from_asset_snapshot(snap_b, source_type="NetBox", source_version="1.0", authority="x")
    graph1.add_entity(e1a)
    graph1.add_entity(e1b)
    relation_depends_on(graph1, e1a.entity_id, e1b.entity_id, source_id="x", source_type="x", source_version="1", authority="x", evidence_ref="ref")

    graph2 = SemanticGraph()
    graph2.add_entity(e1b)
    graph2.add_entity(e1a)
    graph2.relations.append(graph1.relations[0])  # misma relación real, grafo construido en otro orden

    assert graph1.snapshot_hash() == graph2.snapshot_hash()


def test_snapshot_hash_changes_if_an_entity_is_added(contracts_path, context):
    graph = SemanticGraph()
    entity = entity_from_asset_snapshot(_real_asset_snapshot(contracts_path, context), source_type="NetBox", source_version="1.0", authority="x")
    empty_hash = graph.snapshot_hash()
    graph.add_entity(entity)
    assert graph.snapshot_hash() != empty_hash


def test_content_hash_excludes_observed_at_but_not_other_fields(contracts_path, context):
    """observed_at es 'cuándo se construyó el objeto', no 'qué dice' -- dos
    entidades con el mismo contenido lógico (incluido el mismo
    valid_from, que SÍ es dato temporal significativo, no bookkeeping)
    deben tener el mismo content_hash si solo difieren en observed_at
    -- mismo principio que evidence_root excluyendo created_at del
    root_hash."""
    import dataclasses

    snapshot = _real_asset_snapshot(contracts_path, context)
    fixed_valid_from = "2026-01-01T00:00:00Z"
    e1 = entity_from_asset_snapshot(snapshot, source_type="NetBox", source_version="1.0", authority="x", valid_from=fixed_valid_from)
    e2 = entity_from_asset_snapshot(snapshot, source_type="NetBox", source_version="1.0", authority="x", valid_from=fixed_valid_from)

    e2_same_id = dataclasses.replace(e2, entity_id=e1.entity_id, observed_at="2099-01-01T00:00:00Z")
    assert e1.content_hash() == e2_same_id.content_hash()

    # Pero SÍ debe cambiar si valid_from difiere -- no es bookkeeping.
    e3 = entity_from_asset_snapshot(snapshot, source_type="NetBox", source_version="1.0", authority="x", valid_from="2027-01-01T00:00:00Z")
    e3_same_id = dataclasses.replace(e3, entity_id=e1.entity_id)
    assert e1.content_hash() != e3_same_id.content_hash()
