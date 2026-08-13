"""Encadena varios servicios de verdad (no solo cada uno por separado):
normalizer -> correlator -> recommendation -> policy_adapter -> soc_adapter,
usando la salida real de un paso como entrada del siguiente.
"""
from __future__ import annotations

from correlator import build_incident_payload
from evidence_writer import EvidenceWriter, RetentionPolicy
from normalizer import Normalizer, RawEvent
from policy_adapter import InMemoryPolicyDecisionPoint
from recommendation import DeterministicFallbackEngine
from soc_adapter import SOCAdapter


def test_full_pipeline_produces_consistent_chain(contracts_path, context):
    normalizer = Normalizer(contracts_path, context)
    event_result = normalizer.process(
        RawEvent(source="wazuh", native_ref="wazuh://alert/pipeline-1", asset_id="a1", severity_native="14")
    )
    assert event_result.payload["severity_normalized"] == "critical"

    incident = build_incident_payload(contracts_path, context, [event_result.payload])
    assert incident["member_event_ids"] == [event_result.event_id]
    assert incident["severity"] == "critical"

    reco = DeterministicFallbackEngine(contracts_path, context).generate(incident)
    assert reco["incident_id"] == incident["incident_id"]
    assert reco["selected_action"] in {"isolate_kubernetes_workload", "scale_to_zero"}  # critical -> contención

    pdp = InMemoryPolicyDecisionPoint(contracts_path, context, target_allowlist={"deployment/gseg-simulado"})
    decision = pdp.evaluate(
        subject="langgraph", tool=reco["selected_action"], action="execute", target="deployment/gseg-simulado"
    )
    assert decision["result"] == "APPROVAL_REQUIRED"  # nunca ejecución directa (ADR-011)

    evidence = EvidenceWriter(contracts_path, context).write_bytes(
        b"pipeline evidence", media_type="application/json", retention=RetentionPolicy(policy="30d")
    )

    handover = SOCAdapter(contracts_path, context).build_handover(
        incident=incident,
        residual_risk="pendiente de aprobación",
        evidence_manifest_ref=evidence["artifact_id"],
        tlp="AMBER",
    )
    assert handover["evidence_manifest_ref"] == evidence["artifact_id"]
    assert handover["assets"] == ["a1"]
