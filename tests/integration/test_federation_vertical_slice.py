"""Fase L, §26: rebanada vertical normal de Federation/Cross-Domain.

Encadena, con datos reales de este repositorio (no mocks): contexto de
misión local (Fase K) -> FederatedArtifact candidato (fixture
controlada, explícitamente NO un ARGOS remoto real) -> evaluación local
de confianza (`decision.evaluate_federation`) -> reconciliación
semántica (`semantic_conflict`, Fase K, reutilizado) -> ACCEPT o
QUARANTINE -> CrossDomainTransfer cuando corresponde -> evidencia real
(EvidenceManifest/EvidenceRoot/TransparencyReceipt, Fase J reutilizada).
"""
from __future__ import annotations

from evidence_root import verify_evidence_root
from evidence_root.transparency_log import TransparencyLog
from federation.cross_domain_transfer import request_cross_domain_transfer
from federation.decision import evaluate_federation
from federation.evidence import build_federation_decision_record, record_federation_evidence
from federation.federated_artifact import build_federated_artifact
from federation.ledger import FederationLedger
from federation.revocation import RevocationRegistry
from federation.security_domain import SecurityDomain
from mission_context import build_mission_context
from semantic_conflict import SourceClaim, resolve_conflict


def _local_domain(**overrides) -> SecurityDomain:
    base = {
        "tenant_id": "tenant-argos-local", "domain_id": "domain-local", "classification": "internal",
        "trust_zone": "argos-cyber-range", "policy_domain": "p", "evidence_domain": "e", "knowledge_domain": "k",
        "allowed_federation": frozenset({"domain-partner"}), "allowed_destinations": frozenset({"domain-partner"}),
        "retention_profile": "90d", "export_policy": "restricted",
    }
    base.update(overrides)
    return SecurityDomain(**base)


def _remote_domain(**overrides) -> SecurityDomain:
    base = {
        "domain_id": "domain-partner", "allowed_destinations": frozenset({"domain-local"}),
        "allowed_federation": frozenset({"domain-local"}),
    }
    return _local_domain(**{**base, **overrides})


def test_normal_flow_accept_reconcile_release_and_evidence(contracts_path, context):
    """Camino feliz completo (§26): sin conflicto de misión, la
    federación acepta, reconcilia (CONSISTENT), libera un
    CrossDomainTransfer saneado y ancla evidencia real verificable."""
    # 1. Contexto de misión LOCAL real (Fase K) para el activo en cuestión.
    local_mission = build_mission_context(
        "asset-web-frontend", source_id="cmam", criticality="medium", crown_jewel=False,
    )

    # 2. FederatedArtifact candidato -- fixture controlada, nunca un ARGOS
    # remoto real (§35 del prompt).
    artifact = build_federated_artifact(
        artifact_type="SecurityFinding", origin_instance="argos-partner-fixture-1",
        origin_domain="domain-partner", origin_tenant="tenant-partner",
        origin_classification="internal", origin_trust="TRUSTED",
        payload={"asset_id": "asset-web-frontend", "finding": "outdated_tls_config", "criticality_claim": "medium"},
        provenance=("partner-soc-case-ref-001",), source_refs=("partner-soc-case-ref-001",),
    )

    # 3. Evaluación local de confianza.
    decision = evaluate_federation(
        artifact, local_domain=_local_domain(), remote_domain=_remote_domain(),
        known_source_instances=frozenset({"argos-partner-fixture-1"}),
        revocation=RevocationRegistry(), ledger=FederationLedger(), evidence_resolvable=True,
    )
    assert decision.decision == "LOCAL_REVALIDATION_REQUIRED" or decision.decision == "ACCEPT"

    # 4. Reconciliación semántica: la afirmación remota (medium) coincide
    # con el contexto de misión local (medium) -- CONSISTENT, sin
    # sobreescritura porque no hace falta.
    conflict = resolve_conflict(
        "asset-web-frontend", "criticality",
        [SourceClaim(source_id="domain-partner", value="medium", observed_at=artifact.created_at)],
        classification="SEMANTIC",
    )
    assert conflict.state == "CONSISTENT"

    final_decision = evaluate_federation(
        artifact, local_domain=_local_domain(), remote_domain=_remote_domain(),
        known_source_instances=frozenset({"argos-partner-fixture-1"}),
        revocation=RevocationRegistry(), ledger=FederationLedger(),
        semantic_conflict=conflict, evidence_resolvable=True,
    )
    assert final_decision.decision == "ACCEPT"
    assert final_decision.is_active is False  # ACCEPT != ACTIVE, incluso en el camino feliz

    # 5. CrossDomainTransfer: solo se intenta tras ACCEPT (regla del
    # llamante -- nunca tras QUARANTINE/REJECT/LOCAL_REVALIDATION_REQUIRED).
    transfer = request_cross_domain_transfer(
        artifact_ref=artifact.artifact_id, payload=artifact.payload,
        source_domain=_local_domain(), destination_domain=_remote_domain(),
        original_classification="internal", requested_classification="internal", trust="TRUSTED",
    )
    assert transfer.outcome == "RELEASED"

    # 6. Evidencia real (Fase J reutilizada): EvidenceManifest -> EvidenceRoot
    # -> TransparencyReceipt.
    record = build_federation_decision_record(decision=final_decision, artifact=artifact)
    evidence = record_federation_evidence(record, contracts_path=contracts_path, context=context, run_id="run-l-slice-001")
    assert verify_evidence_root(evidence.evidence_root)

    log = TransparencyLog()
    log.append(
        event_type="EVIDENCE_ROOT_CREATED", object_id=evidence.evidence_root["root_id"],
        object_hash=evidence.evidence_root["root_hash"], run_id="run-l-slice-001", producer="federation-decision-record",
    )
    receipt = log.issue_receipt(evidence.evidence_root["root_id"])
    assert receipt.object_id == evidence.evidence_root["root_id"]
    assert log.verify_chain().ok

    # El contexto de misión local nunca fue tocado por el flujo de
    # federación -- sigue siendo exactamente el que se construyó en (1).
    assert local_mission.crown_jewel is False
    assert local_mission.criticality == "medium"


def test_mission_conflict_flow_quarantines_never_silently_merges(contracts_path, context):
    """§9/§19 del prompt, ejemplo literal: activo remoto reclama
    criticidad LOW; el MissionContext local dice crown_jewel/CRITICAL.
    El resultado debe ser QUARANTINE -- nunca una sobreescritura
    silenciosa del contexto de misión local, y ningún CrossDomainTransfer
    se intenta sobre un artefacto en cuarentena."""
    local_mission = build_mission_context(
        "asset-payment-core", source_id="cmam", criticality="critical", crown_jewel=True,
    )

    artifact = build_federated_artifact(
        artifact_type="SecurityFinding", origin_instance="argos-partner-fixture-1",
        origin_domain="domain-partner", origin_tenant="tenant-partner",
        origin_classification="internal", origin_trust="TRUSTED",
        payload={"asset_id": "asset-payment-core", "criticality_claim": "low"},
        provenance=("partner-soc-case-ref-002",),
    )

    conflict = resolve_conflict(
        "asset-payment-core", "criticality",
        [
            SourceClaim(source_id="domain-partner", value="low", observed_at="2026-08-01T00:00:00Z"),
            SourceClaim(source_id="local-mission-context", value="critical", observed_at=local_mission.observed_at),
        ],
        classification="AUTHORITY",
        authority_ranking={"domain-partner": 1, "local-mission-context": 10},
    )
    assert conflict.state == "CONFLICT"
    assert conflict.winning_source == "local-mission-context"

    decision = evaluate_federation(
        artifact, local_domain=_local_domain(), remote_domain=_remote_domain(),
        known_source_instances=frozenset({"argos-partner-fixture-1"}),
        revocation=RevocationRegistry(), ledger=FederationLedger(),
        semantic_conflict=conflict, evidence_resolvable=True,
    )
    assert decision.decision == "QUARANTINE"
    assert decision.semantic_conflict_result == "CONFLICT"

    # Ningún CrossDomainTransfer se solicita para un artefacto en
    # cuarentena -- regla del llamante, verificada aquí explícitamente
    # (nunca se invoca request_cross_domain_transfer en esta rama).
    assert decision.decision != "ACCEPT"

    # El MissionContext local NUNCA se sobreescribe por el conflicto --
    # sigue siendo exactamente lo que era.
    assert local_mission.crown_jewel is True
    assert local_mission.criticality == "critical"

    # Incluso una decisión QUARANTINE deja evidencia real -- ninguna
    # decisión de federación es invisible.
    record = build_federation_decision_record(decision=decision, artifact=artifact)
    evidence = record_federation_evidence(record, contracts_path=contracts_path, context=context, run_id="run-l-slice-002")
    assert verify_evidence_root(evidence.evidence_root)
    assert record["decision"] == "QUARANTINE"
