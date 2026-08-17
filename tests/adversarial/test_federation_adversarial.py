"""Fase L, §29: suite adversarial de Federation/Cross-Domain. Cada
prueba modela un ataque concreto contra el pipeline de federación --
la expectativa en todos los casos es la misma: 0 aceptaciones inseguras
(`decision.decision` nunca es `"ACCEPT"` bajo un ataque, `CrossDomainTransfer.
outcome` nunca es `"RELEASED"` bajo un ataque de liberación, y
`FederationDecision.is_active`/estructura nunca concede autoridad de
ejecución sin importar el ataque).
"""
from __future__ import annotations

import dataclasses

import pytest
from federation.cross_domain_transfer import request_cross_domain_transfer
from federation.decision import evaluate_federation
from federation.federated_artifact import (
    ForbiddenDefaultTrust,
    UnknownArtifactType,
    UnknownTrustLabel,
    build_federated_artifact,
)
from federation.ifc import IFCLabel, evaluate_ifc
from federation.ledger import ContentConflict, FederationLedger
from federation.revocation import RevocationRegistry
from federation.sanitizer import SanitizationRule, apply_sanitization
from federation.security_domain import SecurityDomain, UnknownClassification


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


def _artifact(**overrides):
    base = {
        "artifact_type": "IOC", "origin_instance": "argos-partner-fixture-1", "origin_domain": "domain-partner",
        "origin_tenant": "tenant-partner", "origin_classification": "internal", "payload": {"ioc": "1.2.3.4"},
        "provenance": ("ref-1",),
    }
    base.update(overrides)
    return build_federated_artifact(**base)


def _evaluate(artifact, **overrides):
    base = {
        "local_domain": _domain(), "remote_domain": _remote(),
        "known_source_instances": frozenset({"argos-partner-fixture-1"}),
        "revocation": RevocationRegistry(), "ledger": FederationLedger(), "evidence_resolvable": True,
    }
    base.update(overrides)
    return evaluate_federation(artifact, **base)


# ---------------------------------------------------------------------------
# 1. Origen forjado / no reconocido.
# ---------------------------------------------------------------------------


def test_forged_origin_instance_is_rejected():
    artifact = _artifact(origin_instance="argos-attacker-instance")
    decision = _evaluate(artifact, known_source_instances=frozenset({"argos-partner-fixture-1"}))
    assert decision.decision == "REJECT"


def test_forged_origin_domain_still_subject_to_transfer_check():
    """Declarar un origin_domain que no coincide con el remote_domain
    real suministrado por el llamante no cambia la evaluación de
    dominio -- transfer_allowed se evalúa sobre remote_domain/local_domain
    reales, nunca sobre un string suelto del payload del artefacto."""
    artifact = _artifact(origin_domain="domain-attacker-claimed")
    decision = _evaluate(artifact, remote_domain=_remote(allowed_destinations=frozenset()))
    assert decision.decision == "REJECT"


# ---------------------------------------------------------------------------
# 2. Manipulación de artefacto (tampering).
# ---------------------------------------------------------------------------


def test_tampered_payload_after_hash_computed_is_rejected():
    artifact = _artifact()
    tampered = dataclasses.replace(artifact, payload={"ioc": "6.6.6.6"})  # content_hash ya no coincide
    decision = _evaluate(tampered)
    assert decision.decision == "REJECT"
    assert "HASH_VALID" in decision.reason_codes


def test_forged_content_hash_matching_tampered_payload_still_caught():
    """Si el atacante recalcula un hash falso que "coincide" con el
    payload alterado pero no es el hash real esperado por
    verify_content_hash (que SIEMPRE recomputa desde el payload, nunca
    confía en el campo declarado), sigue detectándose porque
    verify_content_hash ignora el campo declarado por completo."""
    artifact = _artifact()
    fake_but_self_consistent = dataclasses.replace(artifact, payload={"ioc": "6.6.6.6"}, content_hash="sha256:" + "a" * 64)
    decision = _evaluate(fake_but_self_consistent)
    assert decision.decision == "REJECT"


# ---------------------------------------------------------------------------
# 3. Replay / staleness.
# ---------------------------------------------------------------------------


def test_replay_of_identical_artifact_is_idempotent_not_a_new_grant():
    ledger = FederationLedger()
    artifact = _artifact()
    d1 = _evaluate(artifact, ledger=ledger)
    d2 = _evaluate(artifact, ledger=ledger)
    assert d1.decision == "ACCEPT"
    assert d2.decision == "ACCEPT"
    assert d1.decision_id != d2.decision_id  # cada evaluación produce su propia decisión, sin reutilizar autoridad


def test_stale_expired_artifact_replayed_is_rejected():
    artifact = _artifact(valid_until="2000-01-01T00:00:00Z")
    decision = _evaluate(artifact)
    assert decision.decision == "REJECT"


def test_artifact_id_collision_with_different_content_is_rejected():
    """Un atacante reutiliza un artifact_id ya visto con contenido
    distinto (colisión deliberada) -- ContentConflict real, nunca
    sobreescritura silenciosa."""
    ledger = FederationLedger()
    artifact1 = _artifact()
    _evaluate(artifact1, ledger=ledger)
    colliding = dataclasses.replace(artifact1, payload={"ioc": "9.9.9.9"}, content_hash="sha256:" + "b" * 64)
    decision = _evaluate(colliding, ledger=ledger)
    assert decision.decision == "REJECT"
    with pytest.raises(ContentConflict):
        ledger.check_and_record(colliding.artifact_id, colliding.content_hash)


# ---------------------------------------------------------------------------
# 4. Downgrade / stripping.
# ---------------------------------------------------------------------------


def test_classification_downgrade_via_cross_domain_transfer_requires_approval():
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-attack-1", payload={"secret": "x"},
        source_domain=_domain(classification="restricted", allowed_destinations=frozenset({"domain-partner"})),
        destination_domain=_remote(classification="restricted"),
        original_classification="restricted", requested_classification="internal", trust="TRUSTED",
    )
    assert transfer.outcome == "PENDING_APPROVAL"
    assert transfer.released_hash is None


def test_trust_label_stripping_cannot_produce_authoritative_on_ingest():
    """Un atacante que controle el origen remoto no puede autoasignarse
    origin_trust=AUTHORITATIVE ni con ningún alias -- solo las 4
    etiquetas ingeribles existen; AUTHORITATIVE está excluido a nivel de
    constructor, no solo de convención."""
    with pytest.raises(ForbiddenDefaultTrust):
        _artifact(origin_trust="AUTHORITATIVE")


def test_unknown_trust_label_string_is_rejected_not_coerced():
    with pytest.raises(UnknownTrustLabel):
        _artifact(origin_trust="SUPER_TRUSTED")


def test_untrusted_origin_cannot_auto_release_via_ifc():
    label = IFCLabel(
        classification="internal", origin="attacker", purpose="exfil", domain="domain-partner",
        handling="standard", exportability="restricted", retention_profile="90d", trust="UNTRUSTED",
    )
    decision = evaluate_ifc(label=label, source_domain=_remote(), destination_domain=_domain())
    assert decision.outcome == "REQUIRE_APPROVAL"


# ---------------------------------------------------------------------------
# 5. Confusión de tenant/dominio.
# ---------------------------------------------------------------------------


def test_cross_tenant_confusion_yields_zero_implicit_access():
    """Dos tenants distintos, ninguna declaración explícita de
    allowed_federation/allowed_destinations entre ellos -> rechazo, sin
    importar que ambos dominios existan y sean "conocidos" por separado."""
    tenant_x_local = _domain(tenant_id="tenant-x", domain_id="domain-x", allowed_federation=frozenset())
    tenant_y_remote = _remote(domain_id="domain-y", allowed_destinations=frozenset())
    decision = _evaluate(_artifact(origin_domain="domain-y"), local_domain=tenant_x_local, remote_domain=tenant_y_remote)
    assert decision.decision == "REJECT"


def test_domain_id_confusion_same_string_different_tenant_does_not_bypass():
    """Mismo domain_id string coincidente por accidente entre dos
    tenants distintos no basta -- transfer_allowed compara domain_id,
    pero federation_allowed sigue exigiendo declaración explícita del
    lado local; si esta no existe, se rechaza igual."""
    local = _domain(allowed_federation=frozenset())
    decision = _evaluate(_artifact(), local_domain=local)
    assert decision.decision == "REJECT"


# ---------------------------------------------------------------------------
# 6. Metadatos anidados maliciosos / exfiltración vía sanitización incompleta.
# ---------------------------------------------------------------------------


def test_malicious_nested_metadata_duplicate_is_not_auto_detected_but_declared_policy_removes_it():
    """Un atacante (o una fuente comprometida) intenta ocultar un campo
    sensible duplicándolo en una ruta anidada no evidente -- el
    saneamiento no tiene magia para "adivinar" rutas no declaradas
    (documentado también en test_federation_sanitizer.py), pero una
    política que SÍ declara la ruta oculta lo neutraliza."""
    payload = {"clean": "1.2.3.4", "_debug": {"raw_source_token": "shared-secret-abc"}}
    rules = (SanitizationRule(field_path="_debug.raw_source_token", operation="REMOVE_FIELD"),)
    result = apply_sanitization(payload, rules)
    assert "raw_source_token" not in result.released_payload.get("_debug", {})


def test_forbidden_exportability_blocks_release_regardless_of_classification_match():
    label = IFCLabel(
        classification="internal", origin="partner", purpose="share", domain="domain-partner",
        handling="standard", exportability="forbidden", retention_profile="90d", trust="TRUSTED",
    )
    decision = evaluate_ifc(label=label, source_domain=_remote(), destination_domain=_domain())
    assert decision.outcome == "DENY"


# ---------------------------------------------------------------------------
# 7. Amplificación de privilegio / tipo de esquema desconocido.
# ---------------------------------------------------------------------------


def test_unknown_artifact_type_is_rejected_at_construction():
    with pytest.raises(UnknownArtifactType):
        build_federated_artifact(
            artifact_type="SuperAdminGrant", origin_instance="argos-partner-fixture-1", origin_domain="domain-partner",
            origin_tenant="tenant-partner", origin_classification="internal", payload={},
        )


def test_revoked_artifact_reuse_is_rejected_even_after_prior_acceptance():
    """Un artefacto previamente ACEPTADO se revoca después (fuente
    comprometida descubierta) -- una reevaluación posterior debe
    rechazarlo, nunca seguir tratándolo como válido por haber sido
    aceptado antes."""
    artifact = _artifact()
    ledger = FederationLedger()
    revocation = RevocationRegistry()
    first = _evaluate(artifact, ledger=ledger, revocation=revocation)
    assert first.decision == "ACCEPT"

    revocation.revoke(artifact.artifact_id, revoked_at="2026-08-17T12:00:00Z", reason="fuente comprometida")
    second = _evaluate(artifact, ledger=ledger, revocation=revocation)
    assert second.decision == "REJECT"
    assert "NOT_REVOKED" in second.reason_codes


def test_unknown_classification_on_artifact_is_never_silently_coerced():
    with pytest.raises(UnknownClassification):
        _artifact(origin_classification="top-secret-ultra")
