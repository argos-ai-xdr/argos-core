"""federation.cross_domain_transfer: CrossDomainTransfer v1 (Fase L;
prompt maestro de arquitectura objetivo, §10, "CrossDomainTransfer").

Pipeline real (§10): Source -> Domain Policy (`security_domain.
transfer_allowed`) -> IFC (`ifc.evaluate_ifc`) -> Deterministic
Sanitization (`sanitizer.apply_sanitization`) -> Classification Check ->
Approval when required -> `CrossDomainTransfer` -> Destination.

**Ningún LLM declassifica de forma autoritativa.** Toda la lógica de
`classification`/`outcome` de este módulo es determinista y basada en
reglas (`ifc.evaluate_ifc`); no invoca generación ni permite que un
campo de texto libre sobreescriba el resultado de la política.
"""
from __future__ import annotations

import dataclasses
from typing import Literal

from argos_envelope import new_id_prefixed, utc_now_iso

from federation.ifc import IFCLabel, evaluate_ifc
from federation.sanitizer import SanitizationRule, Transformation, apply_sanitization
from federation.security_domain import SecurityDomain

TransferOutcome = Literal["RELEASED", "DENIED", "PENDING_APPROVAL"]


@dataclasses.dataclass(frozen=True)
class CrossDomainTransfer:
    transfer_id: str
    source_domain: str
    destination_domain: str
    artifact_ref: str
    original_classification: str
    requested_classification: str
    released_classification: str | None
    fields_removed: tuple[str, ...]
    transformations: tuple[Transformation, ...]
    policy_ref: str
    decision_ref: str
    approver_ref: str | None
    evidence_ref: str | None
    timestamp: str
    outcome: TransferOutcome
    original_hash: str | None
    released_hash: str | None


def request_cross_domain_transfer(
    *,
    artifact_ref: str,
    payload: dict,
    source_domain: SecurityDomain,
    destination_domain: SecurityDomain,
    original_classification: str,
    requested_classification: str,
    origin: str = "federation",
    purpose: str = "cross_domain_release",
    handling: str = "standard",
    exportability: str = "restricted",
    retention_profile: str = "default",
    trust: str = "EXTERNAL",
    sanitization_rules: tuple[SanitizationRule, ...] = (),
    approver_ref: str | None = None,
    evidence_ref: str | None = None,
    now: str | None = None,
) -> CrossDomainTransfer:
    effective_now = now or utc_now_iso()
    label = IFCLabel(
        classification=original_classification, origin=origin, purpose=purpose,
        domain=source_domain.domain_id, handling=handling, exportability=exportability,
        retention_profile=retention_profile, trust=trust,
    )
    ifc_decision = evaluate_ifc(
        label=label, source_domain=source_domain, destination_domain=destination_domain,
        requested_classification=requested_classification,
    )

    base = {
        "transfer_id": new_id_prefixed("xdxfer"),
        "source_domain": source_domain.domain_id,
        "destination_domain": destination_domain.domain_id,
        "artifact_ref": artifact_ref,
        "original_classification": original_classification,
        "requested_classification": requested_classification,
        "policy_ref": "ifc.evaluate_ifc",
        "decision_ref": ifc_decision.outcome,
        "approver_ref": approver_ref,
        "evidence_ref": evidence_ref,
        "timestamp": effective_now,
    }

    if ifc_decision.outcome == "DENY":
        return CrossDomainTransfer(
            **base, released_classification=None, fields_removed=(), transformations=(),
            outcome="DENIED", original_hash=None, released_hash=None,
        )

    if ifc_decision.outcome == "REQUIRE_APPROVAL" and approver_ref is None:
        return CrossDomainTransfer(
            **base, released_classification=None, fields_removed=(), transformations=(),
            outcome="PENDING_APPROVAL", original_hash=None, released_hash=None,
        )

    # ALLOW, SANITIZE, o REQUIRE_APPROVAL con approver_ref ya suministrado
    # (aprobación previa real, nunca inferida): se procede a liberar.
    sanitized = apply_sanitization(payload, sanitization_rules)
    return CrossDomainTransfer(
        **base, released_classification=requested_classification,
        fields_removed=sanitized.fields_removed, transformations=sanitized.transformations,
        outcome="RELEASED", original_hash=sanitized.original_hash, released_hash=sanitized.released_hash,
    )
