from __future__ import annotations

import pytest
from federation.security_domain import (
    SecurityDomain,
    UnknownClassification,
    federation_allowed,
    transfer_allowed,
)


def _domain(**overrides) -> SecurityDomain:
    base = {
        "tenant_id": "tenant-a",
        "domain_id": "domain-a",
        "classification": "internal",
        "trust_zone": "cyber-range",
        "policy_domain": "argos-a-policy",
        "evidence_domain": "argos-a-evidence",
        "knowledge_domain": "argos-a-knowledge",
        "allowed_federation": frozenset(),
        "allowed_destinations": frozenset(),
        "retention_profile": "90d",
        "export_policy": "restricted",
    }
    base.update(overrides)
    return SecurityDomain(**base)


def test_invalid_classification_is_rejected():
    with pytest.raises(UnknownClassification):
        _domain(classification="top-secret")  # no es uno de los 3 valores reales del envelope


def test_same_domain_transfer_is_always_allowed():
    d = _domain()
    allowed, _ = transfer_allowed(d, d)
    assert allowed is True


def test_cross_domain_transfer_denied_by_default():
    """object.security_domain != target.security_domain NO implica
    transferencia permitida -- deny-by-default real."""
    source = _domain(domain_id="domain-a")
    destination = _domain(domain_id="domain-b")
    allowed, reason = transfer_allowed(source, destination)
    assert allowed is False
    assert "deny-by-default" in reason


def test_cross_domain_transfer_allowed_when_explicitly_declared():
    source = _domain(domain_id="domain-a", allowed_destinations=frozenset({"domain-b"}))
    destination = _domain(domain_id="domain-b")
    allowed, reason = transfer_allowed(source, destination)
    assert allowed is True
    assert "domain-b" in reason


def test_federation_denied_by_default():
    local = _domain(domain_id="domain-a")
    allowed, reason = federation_allowed(local, "domain-remote")
    assert allowed is False
    assert "deny-by-default" in reason


def test_federation_allowed_when_explicitly_declared():
    local = _domain(domain_id="domain-a", allowed_federation=frozenset({"domain-remote"}))
    allowed, _ = federation_allowed(local, "domain-remote")
    assert allowed is True
