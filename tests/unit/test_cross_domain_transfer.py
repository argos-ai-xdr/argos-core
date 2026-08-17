from __future__ import annotations

from federation.cross_domain_transfer import request_cross_domain_transfer
from federation.sanitizer import SanitizationRule
from federation.security_domain import SecurityDomain


def _domain(**overrides) -> SecurityDomain:
    base = {
        "tenant_id": "tenant-a", "domain_id": "domain-a", "classification": "internal",
        "trust_zone": "z", "policy_domain": "p", "evidence_domain": "e", "knowledge_domain": "k",
        "allowed_federation": frozenset(), "allowed_destinations": frozenset({"domain-b"}),
        "retention_profile": "90d", "export_policy": "restricted",
    }
    base.update(overrides)
    return SecurityDomain(**base)


def _remote(**overrides) -> SecurityDomain:
    base = {"domain_id": "domain-b", "classification": "internal", "allowed_destinations": frozenset()}
    return _domain(**{**base, **overrides})


def test_allowed_same_classification_transfer_is_released():
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-1", payload={"ioc": "1.2.3.4"},
        source_domain=_domain(), destination_domain=_remote(),
        original_classification="internal", requested_classification="internal",
        trust="TRUSTED",
    )
    assert transfer.outcome == "RELEASED"
    assert transfer.released_classification == "internal"
    assert transfer.released_hash is not None


def test_domain_not_allowed_is_denied_without_releasing_hash():
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-1", payload={"ioc": "1.2.3.4"},
        source_domain=_domain(allowed_destinations=frozenset()), destination_domain=_remote(),
        original_classification="internal", requested_classification="internal",
    )
    assert transfer.outcome == "DENIED"
    assert transfer.released_classification is None
    assert transfer.released_hash is None
    assert transfer.fields_removed == ()


def test_downgrade_without_approver_is_pending_not_released():
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-1", payload={"ioc": "1.2.3.4"},
        source_domain=_domain(classification="restricted"),
        destination_domain=_remote(classification="restricted"),
        original_classification="restricted", requested_classification="internal",
        trust="TRUSTED",
    )
    assert transfer.outcome == "PENDING_APPROVAL"
    assert transfer.released_classification is None
    assert transfer.released_hash is None


def test_downgrade_with_explicit_approver_is_released():
    """La aprobación debe ser un approver_ref YA suministrado (una
    decisión externa previa), nunca inferida por este módulo."""
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-1", payload={"ioc": "1.2.3.4"},
        source_domain=_domain(classification="restricted"),
        destination_domain=_remote(classification="restricted"),
        original_classification="restricted", requested_classification="internal",
        trust="TRUSTED", approver_ref="approval-001",
    )
    assert transfer.outcome == "RELEASED"
    assert transfer.released_classification == "internal"
    assert transfer.approver_ref == "approval-001"


def test_sanitization_rules_are_applied_before_release():
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-1", payload={"ioc": "1.2.3.4", "reporter_email": "a@b.com"},
        source_domain=_domain(), destination_domain=_remote(),
        original_classification="internal", requested_classification="internal",
        trust="TRUSTED", sanitization_rules=(SanitizationRule(field_path="reporter_email", operation="REMOVE_FIELD"),),
    )
    assert transfer.outcome == "RELEASED"
    assert "reporter_email" in transfer.fields_removed


def test_untrusted_origin_without_approver_is_pending():
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-1", payload={"ioc": "1.2.3.4"},
        source_domain=_domain(), destination_domain=_remote(),
        original_classification="internal", requested_classification="internal",
        trust="UNTRUSTED",
    )
    assert transfer.outcome == "PENDING_APPROVAL"


def test_denied_transfer_preserves_original_and_requested_classification_for_audit():
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-1", payload={"ioc": "1.2.3.4"},
        source_domain=_domain(allowed_destinations=frozenset()), destination_domain=_remote(),
        original_classification="internal", requested_classification="internal",
    )
    assert transfer.original_classification == "internal"
    assert transfer.requested_classification == "internal"


def test_transfer_id_and_timestamp_are_generated():
    transfer = request_cross_domain_transfer(
        artifact_ref="fedart-1", payload={"ioc": "1.2.3.4"},
        source_domain=_domain(), destination_domain=_remote(),
        original_classification="internal", requested_classification="internal", trust="TRUSTED",
    )
    assert transfer.transfer_id
    assert transfer.timestamp
