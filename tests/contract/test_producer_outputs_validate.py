"""Barrido de contrato: cada servicio productor de argos-core produce un
payload que valida contra argos-contracts-scenarios/schemas/. Complementa
(no duplica) los tests unitarios: aquí lo que importa es la lista completa
de "quién produce qué" quedando en un solo sitio, fácil de auditar.
"""
from __future__ import annotations

from asset_reconciler import AssetFragment, build_asset_snapshot_payload
from correlator import build_incident_payload
from evidence_writer import EvidenceWriter, RetentionPolicy
from normalizer import Normalizer, RawEvent
from policy_adapter import InMemoryPolicyDecisionPoint
from recommendation import DeterministicFallbackEngine
from soc_adapter import SOCAdapter
from vulnerability_adapter import VulnerabilityAdapter


def test_normalizer_output_is_security_event(contracts_path, context):
    result = Normalizer(contracts_path, context).process(
        RawEvent(source="wazuh", native_ref="wazuh://alert/c1", severity_native="10")
    )
    assert "event_id" in result.payload


def test_asset_reconciler_output_is_asset_snapshot(contracts_path, context):
    frags = [AssetFragment(source="netbox", asset_id="a1", fields={"namespace": "n"})]
    result = build_asset_snapshot_payload(contracts_path, context, "a1", frags)
    assert result.payload["asset_id"] == "a1"


def test_vulnerability_adapter_output_is_vulnerability_finding(contracts_path, context):
    adapter = VulnerabilityAdapter(contracts_path, context)
    finding = adapter.normalize_trivy_finding(
        {
            "VulnerabilityID": "CVE-2024-0001",
            "PkgName": "x",
            "PURL": "pkg:deb/x@1",
            "asset_id": "a1",
            "source_ref": "s",
        }
    )
    assert finding["finding_id"]


def test_correlator_output_is_incident(contracts_path, context):
    events = [
        {
            "id": "env-c1",
            "event_id": "c1",
            "asset_id": "a1",
            "observed_at": "2026-08-12T10:00:00Z",
            "severity_normalized": "high",
            "source": "wazuh",
        }
    ]
    incident = build_incident_payload(contracts_path, context, events)
    assert incident["incident_id"]


def test_recommendation_output_is_recommendation(contracts_path, context):
    incident = {"incident_id": "inc-c1", "severity": "high", "evidence_refs": []}
    reco = DeterministicFallbackEngine(contracts_path, context).generate(incident)
    assert reco["recommendation_id"]


def test_policy_adapter_output_is_policy_decision(contracts_path, context):
    pdp = InMemoryPolicyDecisionPoint(contracts_path, context, target_allowlist={"t"})
    decision = pdp.evaluate(subject="s", tool="x", action="execute", target="t")
    assert decision["decision_id"]


def test_evidence_writer_output_is_evidence_manifest(contracts_path, context):
    manifest = EvidenceWriter(contracts_path, context).write_bytes(
        b"x", media_type="text/plain", retention=RetentionPolicy(policy="7d")
    )
    assert manifest["artifact_id"]


def test_soc_adapter_output_is_soc_handover(contracts_path, context):
    incident = {"incident_id": "inc-c1", "severity": "high", "timeline": [], "entities": []}
    handover = SOCAdapter(contracts_path, context).build_handover(
        incident=incident, residual_risk="bajo", evidence_manifest_ref="ref", tlp="GREEN"
    )
    assert handover["case_id"]
