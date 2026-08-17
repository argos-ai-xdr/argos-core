"""Fase L, §27: rebanada vertical de seguridad. Prueba el invariante
central de todo Federation (§0/§37 del prompt): un `FederatedArtifact`
aceptado NUNCA concede autoridad de ejecución local. `FederationDecision`
solo describe qué pasa con el ARTEFACTO -- Safety Kernel/Independent
Verifier/OPA/HITL siguen siendo barreras LOCALES obligatorias,
totalmente desacopladas del resultado de federación.
"""
from __future__ import annotations

import dataclasses

from federation.decision import evaluate_federation
from federation.federated_artifact import build_federated_artifact
from federation.ledger import FederationLedger
from federation.revocation import RevocationRegistry
from federation.security_domain import SecurityDomain
from safety_kernel import SafetyCheckInput, evaluate


def _domain(**overrides) -> SecurityDomain:
    base = {
        "tenant_id": "tenant-a", "domain_id": "domain-local", "classification": "internal",
        "trust_zone": "z", "policy_domain": "p", "evidence_domain": "e", "knowledge_domain": "k",
        "allowed_federation": frozenset({"domain-partner"}), "allowed_destinations": frozenset({"domain-partner"}),
        "retention_profile": "90d", "export_policy": "restricted",
    }
    base.update(overrides)
    return SecurityDomain(**base)


def _remote(**overrides) -> SecurityDomain:
    base = {"domain_id": "domain-partner", "allowed_destinations": frozenset({"domain-local"})}
    return _domain(**{**base, **overrides})


def _runbook_artifact(**overrides):
    base = {
        "artifact_type": "ValidatedRunbook", "origin_instance": "argos-partner-fixture-1",
        "origin_domain": "domain-partner", "origin_tenant": "tenant-partner",
        "origin_classification": "internal", "origin_trust": "TRUSTED",
        "payload": {"tool_name": "isolate_kubernetes_workload", "target": "deployment/gseg-simulado"},
        "provenance": ("partner-validated-runbook-ref",),
    }
    base.update(overrides)
    return build_federated_artifact(**base)


def test_structural_safety_check_input_has_no_federation_field():
    """Invariante estructural: `SafetyCheckInput` no tiene NINGÚN campo
    que un FederatedArtifact/FederationDecision pueda rellenar -- no hay
    ruta de código por la que la federación pueda inyectar un hecho de
    seguridad, ni siquiera por accidente."""
    field_names = {f.name for f in dataclasses.fields(SafetyCheckInput)}
    forbidden_substrings = ("federat", "remote", "artifact", "cross_domain")
    for name in field_names:
        for forbidden in forbidden_substrings:
            assert forbidden not in name.lower(), f"{name!r} sugiere una vía de bypass desde federación"


def test_accepted_federated_runbook_alone_never_yields_safe_to_evaluate(contracts_path, context):
    """Un ValidatedRunbook remoto ACEPTADO por Federation, sin ninguna
    revalidación LOCAL adicional aportada, nunca por sí solo produce
    SAFE_TO_EVALUATE -- Safety Kernel exige sus propios 14 hechos reales,
    ninguno de los cuales proviene de FederationDecision."""
    artifact = _runbook_artifact()
    decision = evaluate_federation(
        artifact, local_domain=_domain(), remote_domain=_remote(),
        known_source_instances=frozenset({"argos-partner-fixture-1"}),
        revocation=RevocationRegistry(), ledger=FederationLedger(), evidence_resolvable=True,
    )
    assert decision.decision == "ACCEPT"
    assert decision.is_active is False  # ACCEPT != ACTIVE: no hay promoción a ejecutable

    # Ningún hecho de FederationDecision se traduce en un campo de
    # SafetyCheckInput -- se construye el input "honesto" que un llamante
    # real tendría tras solo una aceptación de federación (sin
    # revalidación local de inventario/catálogo/blast-radius).
    inp = SafetyCheckInput(
        incident={
            "id": "01J0L0000000000000000001", "schema_version": "1.0.0", "observed_at": "2026-08-17T09:00:00Z",
            "producer": "correlator", "classification": "internal", "run_id": "run-l-safety-001",
            "payload_hash": "sha256:" + "0" * 64, "incident_id": "inc-l-safety-001",
            "member_event_ids": ["evt-1"], "timeline": [{"timestamp": "2026-08-17T09:00:00Z", "description": "x"}],
            "entities": [{"type": "asset", "id": "deployment/gseg-simulado"}], "severity": "high",
            "evidence_refs": ["ref-1"],
        },
        recommendation={
            "recommendation_id": "reco-l-safety-001", "incident_id": "inc-l-safety-001",
            "alternatives": [{"action": "isolate_kubernetes_workload", "description": "aislar"}],
            "selected_action": "isolate_kubernetes_workload", "rationale_refs": ["ref-1"],
            "impact": "x", "uncertainty": "baja", "rollback_plan": "revertir",
        },
        target="deployment/gseg-simulado", tool_name="isolate_kubernetes_workload",
        tool_modes=("dry-run", "execute"), side_effect_class="REVERSIBLE_WRITE", rollback_supported=True,
        tool_timeout_seconds=30, tool_known=True, target_allowlist=frozenset({"deployment/gseg-simulado"}),
        # Deliberadamente SIN known_asset_ids/tool_digest_valid/observed_blast_radius_count/
        # no_unresolved_critical_drift/mission_blast_radius: ninguno de estos hechos
        # proviene de -- ni puede inferirse de -- la aceptación de federación.
    )
    result = evaluate(inp, contracts_path=contracts_path, context=context)
    assert result.state == "INCONCLUSIVE"
    assert "target_exists" in result.not_evaluated
    assert "tool_digest_valid" in result.not_evaluated
    assert "blast_radius_bounded" in result.not_evaluated
    assert result.envelope is None  # sin SafetyEnvelope, no hay nada que OPA/HITL puedan siquiera evaluar


def test_unknown_source_runbook_never_bypasses_via_local_revalidation_required(contracts_path, context):
    """Un runbook de una fuente NO reconocida no se acepta a ciegas
    (REJECT determinista, ver test_federation_decision.py) -- pero
    incluso si lo fuera, LOCAL_REVALIDATION_REQUIRED no es una vía de
    autorización: `is_active` sigue siendo False."""
    artifact = _runbook_artifact(evidence_ref=None)
    decision = evaluate_federation(
        artifact, local_domain=_domain(), remote_domain=_remote(),
        known_source_instances=frozenset(),  # fuente no reconocida
        revocation=RevocationRegistry(), ledger=FederationLedger(), evidence_resolvable=True,
    )
    assert decision.decision == "REJECT"
    assert decision.is_active is False


def test_local_revalidation_required_is_not_an_authority_grant():
    """Cuando SÍ falta un hecho legítimamente confirmable (p. ej. la
    evidencia todavía no se pudo resolver), el resultado es
    LOCAL_REVALIDATION_REQUIRED -- no ACCEPT, y en cualquier caso
    is_active permanece False."""
    artifact = _runbook_artifact()
    decision = evaluate_federation(
        artifact, local_domain=_domain(), remote_domain=_remote(),
        known_source_instances=frozenset({"argos-partner-fixture-1"}),
        revocation=RevocationRegistry(), ledger=FederationLedger(), evidence_resolvable=None,
    )
    assert decision.decision == "LOCAL_REVALIDATION_REQUIRED"
    assert decision.is_active is False
