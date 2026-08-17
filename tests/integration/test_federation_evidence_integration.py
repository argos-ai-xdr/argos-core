"""Fase L: integración de Federation con la evidencia real de Fase J --
mismo mecanismo que Fase K (`mission_context.evidence`), sin subsistema
paralelo. Ver el docstring de `federation.evidence` para la nota de
diseño sobre por qué se reutiliza el evento genérico
`EVIDENCE_ROOT_CREATED` en vez de tipos de evento de federación nuevos.
"""
from __future__ import annotations

from evidence_root import verify_evidence_root
from evidence_root.transparency_log import TransparencyLog
from federation.cross_domain_transfer import request_cross_domain_transfer
from federation.decision import evaluate_federation
from federation.evidence import (
    build_cross_domain_transfer_record,
    build_federation_decision_record,
    record_federation_evidence,
)
from federation.federated_artifact import build_federated_artifact
from federation.ledger import FederationLedger
from federation.revocation import RevocationRegistry
from federation.security_domain import SecurityDomain


def _domain(**overrides) -> SecurityDomain:
    base = {
        "tenant_id": "tenant-a", "domain_id": "domain-a", "classification": "internal",
        "trust_zone": "z", "policy_domain": "p", "evidence_domain": "e", "knowledge_domain": "k",
        "allowed_federation": frozenset({"domain-remote"}), "allowed_destinations": frozenset(),
        "retention_profile": "90d", "export_policy": "restricted",
    }
    base.update(overrides)
    return SecurityDomain(**base)


def _remote(**overrides) -> SecurityDomain:
    base = {"domain_id": "domain-remote", "allowed_destinations": frozenset({"domain-a"})}
    return _domain(**{**base, **overrides})


def _artifact(**overrides):
    base = {
        "artifact_type": "DetectionRule", "origin_instance": "argos-remote-1", "origin_domain": "domain-remote",
        "origin_tenant": "tenant-remote", "origin_classification": "internal", "payload": {"rule": "x"},
        "provenance": ("chain-of-custody-ref",),
    }
    base.update(overrides)
    return build_federated_artifact(**base)


def test_federation_decision_evidence_anchors_real_root(contracts_path, context):
    artifact = _artifact()
    decision = evaluate_federation(
        artifact, local_domain=_domain(), remote_domain=_remote(),
        known_source_instances=frozenset({"argos-remote-1"}), revocation=RevocationRegistry(),
        ledger=FederationLedger(), evidence_resolvable=True,
    )
    record = build_federation_decision_record(decision=decision, artifact=artifact)
    evidence = record_federation_evidence(record, contracts_path=contracts_path, context=context, run_id="run-l-001")

    assert verify_evidence_root(evidence.evidence_root)
    assert evidence.evidence_root["artifact_count"] == 1
    assert evidence.manifest["sha256"]


def test_federation_evidence_anchored_via_generic_transparency_event(contracts_path, context):
    """No hay un tipo de evento FEDERATION_ACCEPTED en el log -- se
    ancla con el mismo evento genérico EVIDENCE_ROOT_CREATED que ya usa
    K.1, y el tipo de decisión real vive dentro del record hasheado."""
    artifact = _artifact()
    decision = evaluate_federation(
        artifact, local_domain=_domain(), remote_domain=_remote(),
        known_source_instances=frozenset({"argos-remote-1"}), revocation=RevocationRegistry(),
        ledger=FederationLedger(), evidence_resolvable=True,
    )
    record = build_federation_decision_record(decision=decision, artifact=artifact)
    evidence = record_federation_evidence(record, contracts_path=contracts_path, context=context, run_id="run-l-002")

    log = TransparencyLog()
    entry = log.append(
        event_type="EVIDENCE_ROOT_CREATED", object_id=evidence.evidence_root["root_id"],
        object_hash=evidence.evidence_root["root_hash"], run_id="run-l-002", producer="federation-decision-record",
    )
    receipt = log.issue_receipt(evidence.evidence_root["root_id"])

    assert entry.event_type == "EVIDENCE_ROOT_CREATED"
    assert receipt.object_id == evidence.evidence_root["root_id"]
    assert log.verify_chain().ok
    assert record["decision"] == "ACCEPT"  # el tipo de decisión real vive en el contenido, no en el evento


def test_cross_domain_transfer_evidence_anchors_real_root(contracts_path, context):
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-1", payload={"ioc": "1.2.3.4"},
        source_domain=_domain(allowed_destinations=frozenset({"domain-remote"})), destination_domain=_remote(classification="internal"),
        original_classification="internal", requested_classification="internal", trust="TRUSTED",
    )
    record = build_cross_domain_transfer_record(transfer=transfer)
    evidence = record_federation_evidence(record, contracts_path=contracts_path, context=context, run_id="run-l-003")

    assert verify_evidence_root(evidence.evidence_root)
    assert record["outcome"] == "RELEASED"


def test_denied_cross_domain_transfer_is_still_evidenced():
    """Incluso una transferencia DENEGADA deja un record sellado -- no
    hay decisiones de federación "invisibles" para la evidencia."""
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-1", payload={"ioc": "1.2.3.4"},
        source_domain=_domain(allowed_destinations=frozenset()), destination_domain=_remote(),
        original_classification="internal", requested_classification="internal",
    )
    record = build_cross_domain_transfer_record(transfer=transfer)
    assert record["outcome"] == "DENIED"
    assert record["released_hash"] is None
