from __future__ import annotations

import pytest
from federation.ifc import IFCLabel, evaluate_ifc
from federation.security_domain import SecurityDomain, UnknownClassification


def _domain(**overrides) -> SecurityDomain:
    base = {
        "tenant_id": "tenant-a", "domain_id": "domain-a", "classification": "internal",
        "trust_zone": "z", "policy_domain": "p", "evidence_domain": "e", "knowledge_domain": "k",
        "allowed_federation": frozenset(), "allowed_destinations": frozenset({"domain-b"}),
        "retention_profile": "90d", "export_policy": "restricted",
    }
    base.update(overrides)
    return SecurityDomain(**base)


def _label(**overrides) -> IFCLabel:
    base = {
        "classification": "internal", "origin": "argos-core", "purpose": "test",
        "domain": "domain-a", "handling": "standard", "exportability": "restricted",
        "retention_profile": "90d", "trust": "TRUSTED",
    }
    base.update(overrides)
    return IFCLabel(**base)


def test_unknown_classification_on_label_is_rejected():
    with pytest.raises(UnknownClassification):
        _label(classification="top-secret")


def test_domain_transfer_not_allowed_is_denied():
    source = _domain(allowed_destinations=frozenset())
    destination = _domain(domain_id="domain-b", classification="internal")
    decision = evaluate_ifc(label=_label(), source_domain=source, destination_domain=destination)
    assert decision.outcome == "DENY"
    assert "DOMAIN_TRANSFER_NOT_ALLOWED" in decision.reason_codes


def test_forbidden_exportability_is_denied():
    source = _domain()
    destination = _domain(domain_id="domain-b", classification="internal")
    decision = evaluate_ifc(label=_label(exportability="forbidden"), source_domain=source, destination_domain=destination)
    assert decision.outcome == "DENY"
    assert "EXPORTABILITY_FORBIDDEN" in decision.reason_codes


def test_classification_downgrade_request_requires_approval_never_auto_allowed():
    """§10/§29: pedir liberar bajo una etiqueta MENOS restrictiva que la
    original (restricted -> internal) nunca se concede automáticamente."""
    source = _domain(classification="restricted")
    destination = _domain(domain_id="domain-b", classification="restricted")
    decision = evaluate_ifc(label=_label(classification="restricted"), source_domain=source, destination_domain=destination, requested_classification="internal")
    assert decision.outcome == "REQUIRE_APPROVAL"
    assert "CLASSIFICATION_DOWNGRADE_REQUESTED" in decision.reason_codes


def test_untrusted_origin_requires_approval():
    source = _domain()
    destination = _domain(domain_id="domain-b", classification="internal")
    decision = evaluate_ifc(label=_label(trust="UNTRUSTED"), source_domain=source, destination_domain=destination)
    assert decision.outcome == "REQUIRE_APPROVAL"


def test_unknown_trust_requires_approval_not_treated_as_safe():
    source = _domain()
    destination = _domain(domain_id="domain-b", classification="internal")
    decision = evaluate_ifc(label=_label(trust="UNKNOWN"), source_domain=source, destination_domain=destination)
    assert decision.outcome == "REQUIRE_APPROVAL"


def test_cross_classification_baseline_requires_sanitize():
    source = _domain(classification="internal")
    destination = _domain(domain_id="domain-b", classification="confidential")
    decision = evaluate_ifc(label=_label(classification="internal", trust="TRUSTED"), source_domain=source, destination_domain=destination, requested_classification="confidential")
    assert decision.outcome == "SANITIZE"


def test_same_domain_baseline_trusted_upgrade_or_equal_is_allowed():
    source = _domain(classification="internal")
    destination = _domain(domain_id="domain-b", classification="internal")
    decision = evaluate_ifc(label=_label(classification="internal", trust="TRUSTED"), source_domain=source, destination_domain=destination)
    assert decision.outcome == "ALLOW"


def test_requested_classification_must_be_a_real_enum_value():
    """No hay forma de que un valor de texto libre entre como
    clasificación -- ni desde el label ni desde requested_classification."""
    source = _domain()
    destination = _domain(domain_id="domain-b", classification="internal")
    with pytest.raises(UnknownClassification):
        evaluate_ifc(label=_label(), source_domain=source, destination_domain=destination, requested_classification="whatever-an-llm-said")
