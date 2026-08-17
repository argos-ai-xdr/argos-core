from __future__ import annotations

import dataclasses

from federation.decision import evaluate_federation
from federation.federated_artifact import build_federated_artifact
from federation.ledger import FederationLedger
from federation.revocation import RevocationRegistry
from federation.security_domain import SecurityDomain
from semantic_conflict import SourceClaim, resolve_conflict


def _domain(**overrides) -> SecurityDomain:
    base = {
        "tenant_id": "tenant-a", "domain_id": "domain-a", "classification": "internal",
        "trust_zone": "cyber-range", "policy_domain": "p", "evidence_domain": "e", "knowledge_domain": "k",
        "allowed_federation": frozenset({"domain-remote"}), "allowed_destinations": frozenset(),
        "retention_profile": "90d", "export_policy": "restricted",
    }
    base.update(overrides)
    return SecurityDomain(**base)


def _remote_domain(**overrides) -> SecurityDomain:
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


def _evaluate(artifact=None, *, local=None, remote=None, known=None, revocation=None, ledger=None, conflict=None, evidence_resolvable=True):
    return evaluate_federation(
        artifact or _artifact(),
        local_domain=local or _domain(),
        remote_domain=remote or _remote_domain(),
        known_source_instances=known if known is not None else frozenset({"argos-remote-1"}),
        revocation=revocation or RevocationRegistry(),
        ledger=ledger or FederationLedger(),
        semantic_conflict=conflict,
        evidence_resolvable=evidence_resolvable,
    )


def test_fully_clean_artifact_is_accepted():
    decision = _evaluate()
    assert decision.decision == "ACCEPT"
    assert decision.is_active is False


def test_accept_never_implies_active():
    decision = _evaluate()
    assert decision.decision == "ACCEPT"
    assert decision.is_active is False  # literal del prompt: ACCEPT != ACTIVE


def test_hash_mismatch_is_rejected():
    artifact = _artifact()
    tampered = dataclasses.replace(artifact, payload={"rule": "TAMPERED"})
    decision = _evaluate(tampered)
    assert decision.decision == "REJECT"
    assert "HASH_VALID" in decision.reason_codes


def test_unknown_source_is_rejected_not_silently_accepted():
    """Fuente no reconocida -> violación determinista (source_known es un
    bool, nunca None), nunca se acepta a ciegas ni se cuela como ACCEPT."""
    decision = _evaluate(known=frozenset())
    assert decision.decision == "REJECT"
    assert "SOURCE_KNOWN" in decision.reason_codes


def test_forbidden_source_domain_is_rejected():
    """El dominio remoto no está en allowed_federation del local ->
    deny-by-default real, rechazo."""
    local_without_remote = _domain(allowed_federation=frozenset())
    decision = _evaluate(local=local_without_remote)
    assert decision.decision == "REJECT"
    assert "SOURCE_ALLOWED" in decision.reason_codes


def test_cross_domain_implicit_transfer_is_blocked():
    """object.security_domain != target.security_domain nunca implica
    transferencia permitida -- remote_domain no declara domain-a en sus
    allowed_destinations."""
    remote_without_transfer = _remote_domain(allowed_destinations=frozenset())
    decision = _evaluate(remote=remote_without_transfer)
    assert decision.decision == "REJECT"
    assert "DOMAIN_TRANSFER_ALLOWED" in decision.reason_codes


def test_cross_tenant_does_not_implicitly_grant_access():
    """Dos dominios de tenants distintos sin allowed_federation/
    allowed_destinations explícitos -> rechazo, nunca acceso implícito."""
    tenant_b_local = _domain(tenant_id="tenant-b", domain_id="domain-b", allowed_federation=frozenset())
    decision = _evaluate(local=tenant_b_local)
    assert decision.decision == "REJECT"


def test_expired_artifact_is_rejected_not_silently_accepted():
    artifact = _artifact(valid_until="2020-01-01T00:00:00Z")
    decision = _evaluate(artifact, evidence_resolvable=True)
    assert decision.decision == "REJECT"
    assert "FRESH_ENOUGH" in decision.reason_codes


def test_duplicate_artifact_same_content_is_idempotent():
    artifact = _artifact()
    ledger = FederationLedger()
    d1 = _evaluate(artifact, ledger=ledger)
    d2 = _evaluate(artifact, ledger=ledger)
    assert d1.decision == "ACCEPT"
    assert d2.decision == "ACCEPT"


def test_same_artifact_id_different_content_is_rejected():
    ledger = FederationLedger()
    artifact1 = _artifact()
    _evaluate(artifact1, ledger=ledger)
    artifact2 = dataclasses.replace(artifact1, payload={"rule": "CHANGED"}, content_hash="sha256:" + "e" * 64)
    decision = _evaluate(artifact2, ledger=ledger)
    assert decision.decision == "REJECT"
    assert "NO_REPLAY_CONFLICT" in decision.reason_codes


def test_revoked_artifact_is_rejected():
    artifact = _artifact()
    revocation = RevocationRegistry()
    revocation.revoke(artifact.artifact_id, revoked_at="2026-08-17T10:00:00Z")
    decision = _evaluate(artifact, revocation=revocation)
    assert decision.decision == "REJECT"
    assert "NOT_REVOKED" in decision.reason_codes


def test_missing_evidence_resolvability_requires_local_revalidation():
    decision = _evaluate(evidence_resolvable=None)
    assert decision.decision == "LOCAL_REVALIDATION_REQUIRED"
    assert "evidence_resolvable" in decision.required_revalidation


def test_semantic_conflict_leads_to_quarantine_not_silent_merge():
    """El ejemplo literal del prompt: remote asset-X criticality LOW vs
    local asset-X crown_jewel CRITICAL -> CONFLICT, nunca sobreescritura
    silenciosa."""
    conflict = resolve_conflict(
        "asset-x", "criticality",
        [SourceClaim(source_id="remote", value="LOW", observed_at="2026-01-01T00:00:00Z"), SourceClaim(source_id="local", value="CRITICAL", observed_at="2026-06-01T00:00:00Z")],
        classification="AUTHORITY",
        authority_ranking={"remote": 1, "local": 10},
    )
    assert conflict.state == "CONFLICT"
    decision = _evaluate(conflict=conflict)
    assert decision.decision == "QUARANTINE"
    assert decision.semantic_conflict_result == "CONFLICT"


def test_requires_authority_conflict_also_quarantines():
    conflict = resolve_conflict("asset-x", "criticality", [SourceClaim(source_id="remote", value="LOW", observed_at="2026-01-01T00:00:00Z"), SourceClaim(source_id="local", value="HIGH", observed_at="2026-01-01T00:00:00Z")], classification="AUTHORITY")
    assert conflict.state == "REQUIRES_AUTHORITY"
    decision = _evaluate(conflict=conflict)
    assert decision.decision == "QUARANTINE"


def test_consistent_conflict_result_does_not_block_accept():
    conflict = resolve_conflict("asset-x", "criticality", [SourceClaim(source_id="remote", value="HIGH", observed_at="2026-01-01T00:00:00Z")], classification="AUTHORITY")
    assert conflict.state == "CONSISTENT"
    decision = _evaluate(conflict=conflict)
    assert decision.decision == "ACCEPT"


def test_violation_always_outweighs_unevaluated_and_conflict():
    """Fail-closed real: una violación conocida (hash inválido) pesa más
    que cualquier otra señal, incluidas las de conflicto/desconocido."""
    artifact = _artifact()
    tampered = dataclasses.replace(artifact, payload={"rule": "TAMPERED"})
    conflict = resolve_conflict("x", "y", [SourceClaim(source_id="a", value="1", observed_at="t")], classification="SEMANTIC")
    decision = _evaluate(tampered, conflict=conflict, evidence_resolvable=None)
    assert decision.decision == "REJECT"


def test_decision_never_contains_an_authority_field():
    """Estructural: FederationDecision no tiene ningún campo de
    autorización de ejecución -- solo describe qué pasa con el
    ARTEFACTO, nunca concede permiso de acción."""
    decision = _evaluate()
    field_names = {f.name for f in dataclasses.fields(decision)}
    assert "approved" not in field_names
    assert "execution_allowed" not in field_names
    assert "policy_decision" not in field_names
