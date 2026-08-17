"""federation.federated_artifact: FederatedArtifact v1 determinista
(Fase L; prompt maestro de arquitectura objetivo, "FEDERATED ARTIFACT").

**Invariante crítico (§12 del prompt)**: un artefacto federado nunca se
construye con `origin_trust=AUTHORITATIVE` — esa etiqueta solo puede
asignarla una decisión LOCAL explícita y posterior (p. ej. tras
revalidación completa), nunca el propio origen remoto. Un peer de
federación confiable + un artefacto válido NO implica autoridad
operacional local automática.

Sin contrato v1 cross-repo todavía — nada fuera de `argos-core` lo
consume (mismo criterio que `evidence_root`/`mission_context`).
"""
from __future__ import annotations

import dataclasses
import hashlib
import json

from argos_envelope import new_id_prefixed, utc_now_iso

ARTIFACT_TYPES = frozenset(
    {
        "IOC", "TTP", "DetectionRule", "AttackPattern", "ValidatedRunbook",
        "SecurityFinding", "ModelEvaluation", "KnowledgeArtifact", "SemanticContextFragment",
    }
)

#: §12 del prompt. AUTHORITATIVE deliberadamente excluido de los valores
#: que `build_federated_artifact` puede aceptar como `origin_trust` de
#: entrada -- ver `ForbiddenDefaultTrust`.
TRUST_LABELS = ("AUTHORITATIVE", "TRUSTED", "EXTERNAL", "UNTRUSTED", "UNKNOWN")
INGESTABLE_TRUST_LABELS = ("TRUSTED", "EXTERNAL", "UNTRUSTED", "UNKNOWN")


class UnknownArtifactType(ValueError):
    pass


class UnknownTrustLabel(ValueError):
    pass


class ForbiddenDefaultTrust(ValueError):
    """Un artefacto recién ingerido no puede declararse AUTHORITATIVE --
    esa promoción, si alguna vez ocurre, es un acto LOCAL posterior y
    explícito, nunca un valor que el origen remoto pueda autoasignarse."""


@dataclasses.dataclass(frozen=True)
class FederatedArtifact:
    artifact_id: str
    artifact_type: str
    origin_instance: str
    origin_domain: str
    origin_tenant: str
    origin_classification: str
    origin_trust: str
    source_refs: tuple[str, ...]
    payload: dict
    content_hash: str
    schema_version: str
    created_at: str
    valid_from: str
    valid_until: str | None
    handling: str
    exportability: str
    provenance: tuple[str, ...]
    evidence_ref: str | None
    parent_artifact: str | None

    def to_dict(self) -> dict:
        return {**dataclasses.asdict(self), "source_refs": list(self.source_refs), "provenance": list(self.provenance)}


def _content_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_federated_artifact(
    *,
    artifact_type: str,
    origin_instance: str,
    origin_domain: str,
    origin_tenant: str,
    origin_classification: str,
    payload: dict,
    origin_trust: str = "EXTERNAL",
    source_refs: tuple[str, ...] = (),
    valid_from: str | None = None,
    valid_until: str | None = None,
    handling: str = "standard",
    exportability: str = "restricted",
    provenance: tuple[str, ...] = (),
    evidence_ref: str | None = None,
    parent_artifact: str | None = None,
    schema_version: str = "1.0.0",
) -> FederatedArtifact:
    if artifact_type not in ARTIFACT_TYPES:
        raise UnknownArtifactType(f"{artifact_type!r} no es un tipo de artefacto federado soportado: {sorted(ARTIFACT_TYPES)}")
    if origin_trust == "AUTHORITATIVE":
        raise ForbiddenDefaultTrust("origin_trust=AUTHORITATIVE no puede asignarse al ingerir un artefacto federado (§12) -- solo una decisión local posterior puede promoverlo")
    if origin_trust not in INGESTABLE_TRUST_LABELS:
        raise UnknownTrustLabel(f"{origin_trust!r} no es una etiqueta de confianza ingerible: {INGESTABLE_TRUST_LABELS}")

    now = utc_now_iso()
    return FederatedArtifact(
        artifact_id=new_id_prefixed("fedart"),
        artifact_type=artifact_type,
        origin_instance=origin_instance,
        origin_domain=origin_domain,
        origin_tenant=origin_tenant,
        origin_classification=origin_classification,
        origin_trust=origin_trust,
        source_refs=source_refs,
        payload=payload,
        content_hash=_content_hash(payload),
        schema_version=schema_version,
        created_at=now,
        valid_from=valid_from or now,
        valid_until=valid_until,
        handling=handling,
        exportability=exportability,
        provenance=provenance,
        evidence_ref=evidence_ref,
        parent_artifact=parent_artifact,
    )


def verify_content_hash(artifact: FederatedArtifact) -> bool:
    """Recomputa el hash desde el payload real -- nunca confía en el
    campo `content_hash` que ya trae el artefacto (mismo principio que
    `evidence_root.verify_evidence_root`)."""
    return _content_hash(artifact.payload) == artifact.content_hash
