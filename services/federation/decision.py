"""federation.decision: evaluación local de confianza + FederationDecision
v1 (Fase L; prompt maestro de arquitectura objetivo, "FEDERATION
DECISION", "LOCAL TRUST EVALUATION").

**Principio central (§0 del prompt): la federación transporta
información, nunca autoridad.** `evaluate_federation` nunca produce
`ACTIVE`, nunca produce una `Approval`, nunca autoriza ejecución — solo
decide si un `FederatedArtifact` entra en un contexto local controlado
(`ACCEPT`), se aísla para revisión (`QUARANTINE`), se descarta
(`REJECT`), o exige revalidación local antes de usarse
(`LOCAL_REVALIDATION_REQUIRED`). **`ACCEPT != ACTIVE`**: promoción a uso
operacional sigue siendo un proceso local aparte, no modelado aquí.

Reutiliza `semantic_conflict.resolve_conflict` (Fase K) para el eje de
conflicto semántico/de misión — no crea un segundo motor de conflictos.

Ninguna dimensión de confianza se promedia. Un `False` (violación
conocida) en cualquier dimensión pesa más que cualquier cantidad de
dimensiones `True` — mismo criterio fail-closed que `safety_kernel`/
`independent_verifier`.
"""
from __future__ import annotations

import dataclasses
from typing import Literal

from argos_envelope import new_id_prefixed, utc_now_iso
from federation.federated_artifact import FederatedArtifact, verify_content_hash
from federation.ledger import ContentConflict, FederationLedger
from federation.revocation import RevocationRegistry
from federation.security_domain import SecurityDomain, federation_allowed, transfer_allowed
from semantic_conflict import SemanticConflict

FederationOutcome = Literal["ACCEPT", "QUARANTINE", "REJECT", "LOCAL_REVALIDATION_REQUIRED"]


@dataclasses.dataclass(frozen=True)
class TrustDimension:
    name: str
    passed: bool | None  # None = UNKNOWN/no confirmable
    detail: str


@dataclasses.dataclass(frozen=True)
class FederationDecision:
    decision_id: str
    artifact_ref: str
    local_domain: str
    decision: FederationOutcome
    reason_codes: tuple[str, ...]
    policy_refs: tuple[str, ...]
    classification_result: str
    trust_result: str
    provenance_result: str
    freshness_result: str
    semantic_conflict_result: str
    required_revalidation: tuple[str, ...]
    decision_time: str
    evidence_refs: tuple[str, ...]

    @property
    def is_active(self) -> bool:
        """Siempre False -- ninguna FederationDecision otorga ACTIVE por
        sí misma (§6 del prompt: ACCEPT != ACTIVE). Existe como propiedad
        explícita para que un test pueda afirmarlo, no solo un comentario."""
        return False


def _evaluate_dimensions(
    artifact: FederatedArtifact,
    *,
    local_domain: SecurityDomain,
    remote_domain: SecurityDomain,
    known_source_instances: frozenset[str],
    revocation: RevocationRegistry,
    ledger: FederationLedger,
    now: str,
    evidence_resolvable: bool | None,
) -> tuple[TrustDimension, ...]:
    hash_valid = verify_content_hash(artifact)

    provenance_present = bool(artifact.provenance) or bool(artifact.source_refs)

    source_known = artifact.origin_instance in known_source_instances
    fed_allowed, fed_reason = federation_allowed(local_domain, remote_domain.domain_id)

    classification_compatible = artifact.origin_classification in ("internal", "confidential", "restricted")

    domain_ok, domain_reason = transfer_allowed(remote_domain, local_domain)

    if artifact.valid_until is not None and now > artifact.valid_until:
        fresh_enough = False
        freshness_detail = f"expirado: valid_until={artifact.valid_until!r} < now={now!r}"
    else:
        fresh_enough = True
        freshness_detail = f"vigente (valid_until={artifact.valid_until!r})"

    is_revoked = revocation.is_revoked(artifact.artifact_id)

    not_tainted_as_authoritative = artifact.origin_trust != "AUTHORITATIVE"  # invariante estructural (ya lo impide build_federated_artifact, pero se re-verifica aquí también)

    try:
        ledger.check_and_record(artifact.artifact_id, artifact.content_hash)
        no_replay_conflict = True
        replay_detail = "sin conflicto de replay"
    except ContentConflict as exc:
        no_replay_conflict = False
        replay_detail = str(exc)

    return (
        TrustDimension("schema_valid", True, "estructura de FederatedArtifact válida (construcción tipada)"),
        TrustDimension("hash_valid", hash_valid, "content_hash recomputado coincide" if hash_valid else "content_hash NO coincide con el payload real"),
        TrustDimension("provenance_present", provenance_present, f"provenance={list(artifact.provenance)}, source_refs={list(artifact.source_refs)}"),
        TrustDimension("source_known", source_known, f"origin_instance {artifact.origin_instance!r} {'conocido' if source_known else 'NO reconocido'}"),
        TrustDimension("source_allowed", fed_allowed, fed_reason),
        TrustDimension("classification_compatible", classification_compatible, f"origin_classification={artifact.origin_classification!r}"),
        TrustDimension("domain_transfer_allowed", domain_ok, domain_reason),
        TrustDimension("fresh_enough", fresh_enough, freshness_detail),
        TrustDimension("not_revoked", not is_revoked, f"revocado en {revocation.revoked_at(artifact.artifact_id)!r}" if is_revoked else "sin revocar"),
        TrustDimension("not_authoritative_by_default", not_tainted_as_authoritative, f"origin_trust={artifact.origin_trust!r}"),
        TrustDimension("no_replay_conflict", no_replay_conflict, replay_detail),
        TrustDimension("evidence_resolvable", evidence_resolvable, "no re-suministrado" if evidence_resolvable is None else str(evidence_resolvable)),
    )


def evaluate_federation(
    artifact: FederatedArtifact,
    *,
    local_domain: SecurityDomain,
    remote_domain: SecurityDomain,
    known_source_instances: frozenset[str],
    revocation: RevocationRegistry,
    ledger: FederationLedger,
    semantic_conflict: SemanticConflict | None = None,
    evidence_resolvable: bool | None = None,
    now: str | None = None,
) -> FederationDecision:
    effective_now = now or utc_now_iso()
    dimensions = _evaluate_dimensions(
        artifact,
        local_domain=local_domain,
        remote_domain=remote_domain,
        known_source_instances=known_source_instances,
        revocation=revocation,
        ledger=ledger,
        now=effective_now,
        evidence_resolvable=evidence_resolvable,
    )

    violated = [d for d in dimensions if d.passed is False]
    unevaluated = [d for d in dimensions if d.passed is None]

    conflict_state = semantic_conflict.state if semantic_conflict is not None else "UNKNOWN"

    reason_codes: list[str] = [d.name.upper() for d in violated]
    required_revalidation: list[str] = [d.name for d in unevaluated]

    if violated:
        decision: FederationOutcome = "REJECT"
    elif conflict_state in ("CONFLICT", "REQUIRES_AUTHORITY"):
        decision = "QUARANTINE"
        reason_codes.append(f"SEMANTIC_{conflict_state}")
    elif unevaluated:
        decision = "LOCAL_REVALIDATION_REQUIRED"
    else:
        decision = "ACCEPT"

    return FederationDecision(
        decision_id=new_id_prefixed("feddec"),
        artifact_ref=artifact.artifact_id,
        local_domain=local_domain.domain_id,
        decision=decision,
        reason_codes=tuple(reason_codes),
        policy_refs=("security_domain.transfer_allowed", "security_domain.federation_allowed"),
        classification_result="OK" if any(d.name == "classification_compatible" and d.passed for d in dimensions) else "MISMATCH",
        trust_result="OK" if not violated else "VIOLATION",
        provenance_result="OK" if any(d.name == "provenance_present" and d.passed for d in dimensions) else "INSUFFICIENT",
        freshness_result="OK" if any(d.name == "fresh_enough" and d.passed for d in dimensions) else "EXPIRED",
        semantic_conflict_result=conflict_state,
        required_revalidation=tuple(required_revalidation),
        decision_time=effective_now,
        evidence_refs=artifact.source_refs,
    )
