"""Fase K, vertical slice real: activo → servicio/misión → conocimiento
temporal → resolución de autoridad/conflicto → blast radius → consumo de
Safety Kernel → EvidenceManifest → EvidenceRoot → Transparency entry.

Reutiliza literalmente la infraestructura de Fase J (evidence_writer,
evidence_root, transparency_log) — ningún mecanismo de evidencia
paralelo. Reutiliza asset_reconciler (ARG-010) para el activo real, no
un fixture inventado desde cero.
"""
from __future__ import annotations

from argos_envelope import EnvelopeContext
from asset_reconciler import AssetFragment, build_asset_snapshot_payload
from evidence_root import verify_evidence_root
from evidence_root.transparency_log import TransparencyLog
from mission_context import assess_blast_radius, build_mission_context
from mission_context.evidence import build_mission_decision_record, record_mission_decision_evidence
from safety_kernel import SafetyCheckInput, evaluate
from semantic_conflict import SourceClaim, resolve_conflict
from semantic_graph import SemanticGraph, entity_from_asset_snapshot
from temporal_knowledge import TemporalKnowledgeBase, make_fact


def _incident(**overrides):
    base = {
        "id": "01J0MSN0000000000000001",
        "schema_version": "1.0.0",
        "observed_at": "2026-08-17T09:00:00Z",
        "producer": "correlator",
        "classification": "internal",
        "run_id": "run-mission-001",
        "payload_hash": "sha256:" + "0" * 64,
        "incident_id": "inc-mission-001",
        "member_event_ids": ["evt-1"],
        "timeline": [{"timestamp": "2026-08-17T09:00:00Z", "description": "x"}],
        "entities": [{"type": "asset", "id": "asset-gseg-01"}],
        "severity": "critical",
        "evidence_refs": ["fixtures/smoke/security-event/wazuh-alert-001.json"],
    }
    base.update(overrides)
    return base


def test_full_semantic_mission_vertical_slice(contracts_path):
    run_id = "run-mission-001"
    context = EnvelopeContext(producer="mission-decision", run_id=run_id)

    # 1. Activo real (reutiliza asset_reconciler, ARG-010) con conflicto
    #    entre fuentes resuelto por autoridad gobernada (K4/K5).
    fragments = [
        AssetFragment(source="cmam", asset_id="asset-gseg-01", fields={"namespace": "argos-cyber-range", "criticality_esp": "high"}),
        AssetFragment(source="legacy-cmdb", asset_id="asset-gseg-01", fields={"criticality_esp": "low"}),
    ]
    reconcile_result = build_asset_snapshot_payload(
        contracts_path, context, "asset-gseg-01", fragments, authority_ranking={"cmam": 10, "legacy-cmdb": 1}
    )
    assert reconcile_result.payload["criticality_esp"] == "high"  # cmam gana por autoridad
    assert reconcile_result.conflicts[0]["resolution"]["winning_source"] == "cmam"

    # 2. Grafo semántico (K1): entidad Asset real desde el AssetSnapshot ya reconciliado.
    graph = SemanticGraph()
    asset_entity = entity_from_asset_snapshot(reconcile_result.payload, source_type="CMAM", source_version="1.0", authority="cmam-authoritative")
    graph.add_entity(asset_entity)
    snapshot_hash_before = graph.snapshot_hash()

    # 3. Conocimiento temporal (K3): "qué sabía ARGOS" sobre la
    #    criticidad de este activo en un instante anterior a la resolución.
    kb = TemporalKnowledgeBase()
    kb.add_fact(make_fact("asset-gseg-01", "criticality", "medium", source_id="cmam", observed_at="2026-06-01T00:00:00Z", valid_from="2026-06-01T00:00:00Z"))
    kb.add_fact(make_fact("asset-gseg-01", "criticality", "high", source_id="cmam", observed_at="2026-08-17T09:00:00Z", valid_from="2026-08-17T09:00:00Z"))
    query_time = "2026-08-17T09:00:00Z"
    temporal_fact = kb.query_at("asset-gseg-01", "criticality", query_time)
    assert temporal_fact.value == "high"
    # Consultar un instante anterior a que ARGOS lo supiera no filtra el dato nuevo.
    assert kb.query_at("asset-gseg-01", "criticality", "2026-07-01T00:00:00Z").value == "medium"

    # 4. Conflicto semántico explícito sobre el MISMO atributo, para el
    #    registro de decisión (K4/K5) -- reutiliza la misma política de autoridad.
    conflict = resolve_conflict(
        "asset-gseg-01", "criticality",
        [SourceClaim(source_id="cmam", value="high", observed_at="2026-08-17T09:00:00Z"), SourceClaim(source_id="legacy-cmdb", value="low", observed_at="2026-01-01T00:00:00Z")],
        classification="CLASSIFICATION",
        authority_ranking={"cmam": 10, "legacy-cmdb": 1},
    )
    assert conflict.state == "CONFLICT"
    assert conflict.winning_source == "cmam"

    # 5. Mission Context real (K2) -- crown-jewel, criticidad alta.
    mission_ctx = build_mission_context(
        "asset-gseg-01", source_id="mission-registry", criticality="high", crown_jewel=True,
        acceptable_degradation="ninguna", maximum_outage="PT30M", recovery_priority=1,
    )

    # 6. Blast radius extendido (K6) -- technical_affected_count simula
    #    lo que graph.blast_radius.py (argos-cyber-tools) ya calcularía de verdad.
    blast_radius = assess_blast_radius(
        mission_context=mission_ctx, technical_affected_count=3,
        technical_evidence_refs=("networkpolicy/argos-cyber-range/default-deny", "rolebinding/argos-cyber-range/gseg-binding"),
    )
    assert blast_radius.mission_blast_radius == "CRITICAL"  # crown-jewel + impacto real

    # 7. Consumo por Safety Kernel (K7) -- MissionContext nunca decide autorización.
    sk_input = SafetyCheckInput(
        incident=_incident(),
        recommendation={
            "recommendation_id": "reco-mission-001", "incident_id": "inc-mission-001",
            "alternatives": [{"action": "isolate_kubernetes_workload", "description": "aislar"}],
            "selected_action": "isolate_kubernetes_workload", "rationale_refs": ["ref-1"],
            "impact": "x", "uncertainty": "baja", "rollback_plan": "revertir",
        },
        target="deployment/gseg-simulado", tool_name="isolate_kubernetes_workload",
        tool_modes=("dry-run", "execute"), side_effect_class="REVERSIBLE_WRITE", rollback_supported=True,
        tool_timeout_seconds=30, tool_known=True, target_allowlist=frozenset({"deployment/gseg-simulado"}),
        mission_blast_radius=blast_radius.mission_blast_radius,
    )
    sk_decision = evaluate(sk_input, contracts_path=contracts_path, context=context)
    assert "mission_impact_bounded" in sk_decision.violated  # CRITICAL nunca se considera acotado
    assert sk_decision.state == "BLOCKED"  # una violación real -- ni siquiera INCONCLUSIVE

    # 8. Registro de decisión + evidencia (K9), reutilizando Fase J tal cual.
    record = build_mission_decision_record(
        entity_id="asset-gseg-01", semantic_graph=graph, mission_context=mission_ctx,
        temporal_query_time=query_time, conflicts=[conflict], blast_radius=blast_radius,
        safety_kernel_state=sk_decision.state, safety_kernel_reason=sk_decision.reason,
        unknowns=sk_decision.not_evaluated,
    )
    evidence = record_mission_decision_evidence(record, contracts_path=contracts_path, context=context, run_id=run_id)
    assert verify_evidence_root(evidence.evidence_root)
    assert evidence.record["semantic_graph_snapshot_hash"] == snapshot_hash_before
    assert evidence.record["blast_radius_result"]["mission_blast_radius"] == "CRITICAL"
    assert evidence.record["safety_kernel_state"] == "BLOCKED"

    # 9. Transparency Log (Fase J) real sobre esta decisión.
    log = TransparencyLog()
    log.append(event_type="EVIDENCE_ROOT_CREATED", object_id=evidence.evidence_root["root_id"], object_hash=evidence.evidence_root["root_hash"], run_id=run_id, producer="mission-decision")
    receipt = log.issue_receipt(evidence.evidence_root["root_id"])
    assert receipt.event_type == "EVIDENCE_ROOT_CREATED"
    assert log.verify_chain().ok

    # 10. Invariante cruzado K: un cambio POSTERIOR al grafo no reescribe
    #     lo que ARGOS sabía en el momento de esta decisión.
    other_asset = entity_from_asset_snapshot(
        build_asset_snapshot_payload(contracts_path, context, "asset-other", [AssetFragment(source="cmam", asset_id="asset-other", fields={"namespace": "x"})]).payload,
        source_type="CMAM", source_version="1.0", authority="cmam-authoritative",
    )
    graph.add_entity(other_asset)  # el grafo EN MEMORIA cambia...
    assert graph.snapshot_hash() != snapshot_hash_before  # ...pero el hash nuevo es distinto...
    assert evidence.record["semantic_graph_snapshot_hash"] == snapshot_hash_before  # ...y el record ya anclado NUNCA se reescribe
    assert verify_evidence_root(evidence.evidence_root)  # el EvidenceRoot ya sellado sigue verificando igual
