"""evidence_root: agregador determinista de EvidenceManifest ya reales
(ADR-023, ADR-017 Fase J; prompt maestro de arquitectura objetivo,
"EvidenceRoot").

**Decisión de diseño (sin Merkle)**: ningún contrato existente de este
proyecto exige un árbol de Merkle. El precedente directo ya establecido
en `argos-validation/harness/acceptance.py::seal_report` usa un hash
agregado determinista sobre JSON canónico — este módulo sigue el MISMO
mecanismo (`sort_keys=True`, sha256) en vez de introducir Merkle por
sofisticación. Si un contrato futuro lo exige explícitamente, se
evalúa entonces (mismo criterio de ADR-017/ADR-020/ADR-021: nada se
construye por adelantado sin necesidad real).

No es "EvidenceRoot" como estructura desplegada con firma real — es el
agregador lógico. `algorithm`/`canonicalization` son campos explícitos
del payload precisamente para no cerrar la puerta a crypto-agility
futura (un algoritmo distinto de sha256 no rompería el contrato, solo
cambiaría el valor de esos dos campos).
"""
from __future__ import annotations

import dataclasses
import hashlib
import json

from argos_envelope import new_id_prefixed, utc_now_iso

ALGORITHM = "sha256"
CANONICALIZATION = "sorted-json-by-sha256.v1"


class InconsistentEvidenceRoot(Exception):
    """Dos manifiestos declaran el mismo artifact_id con sha256 distinto
    -- corrupción o manipulación, nunca se resuelve en silencio eligiendo
    uno de los dos."""


class MissingCriticalEvidence(Exception):
    """Un manifiesto es None/incompleto y el llamante pidió modo crítico
    (critical=True) -- nunca se sustituye por un placeholder "UNKNOWN"."""


@dataclasses.dataclass(frozen=True)
class ArtifactRef:
    artifact_id: str
    sha256: str
    object_ref: str

    def to_dict(self) -> dict:
        return {"artifact_id": self.artifact_id, "sha256": self.sha256, "object_ref": self.object_ref}


def _artifact_ref_from_manifest(manifest: dict) -> ArtifactRef:
    return ArtifactRef(
        artifact_id=manifest["artifact_id"],
        sha256=manifest["sha256"],
        object_ref=manifest["object_ref"],
    )


def _canonical_hash(refs: list[ArtifactRef]) -> str:
    ordered = sorted((r.to_dict() for r in refs), key=lambda r: (r["sha256"], r["artifact_id"]))
    canonical = json.dumps(ordered, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_evidence_root(
    manifests: list[dict | None],
    *,
    run_id: str,
    producer: str,
    incident_id: str | None = None,
    release_ref: str | None = None,
    critical: bool = True,
) -> dict:
    """`manifests`: EvidenceManifest v1 payloads ya validados y reales
    (p. ej. producidos por `evidence_writer.EvidenceWriter.write_bytes`).
    El orden de la lista NO afecta `root_hash` -- se reordena por sha256
    antes de hashear. Duplicados exactos (mismo artifact_id Y mismo
    sha256) se deduplican en silencio (es el mismo artefacto referenciado
    dos veces, no una inconsistencia); duplicados CONFLICTIVOS (mismo
    artifact_id, sha256 distinto) siempre lanzan
    `InconsistentEvidenceRoot`, sin importar `critical`."""
    by_id: dict[str, ArtifactRef] = {}
    for manifest in manifests:
        if manifest is None or not manifest.get("artifact_id") or not manifest.get("sha256"):
            if critical:
                raise MissingCriticalEvidence(f"manifiesto ausente o incompleto en modo crítico: {manifest!r}")
            continue
        ref = _artifact_ref_from_manifest(manifest)
        existing = by_id.get(ref.artifact_id)
        if existing is not None and existing.sha256 != ref.sha256:
            raise InconsistentEvidenceRoot(
                f"artifact_id {ref.artifact_id!r} declarado con sha256 distintos: {existing.sha256!r} vs {ref.sha256!r}"
            )
        by_id[ref.artifact_id] = ref

    refs = list(by_id.values())
    root_hash = _canonical_hash(refs)
    root_id = new_id_prefixed("root")

    return {
        "root_id": root_id,
        "run_id": run_id,
        "incident_id": incident_id,
        "algorithm": ALGORITHM,
        "canonicalization": CANONICALIZATION,
        "artifact_count": len(refs),
        "artifact_refs": sorted((r.to_dict() for r in refs), key=lambda r: (r["sha256"], r["artifact_id"])),
        "root_hash": root_hash,
        "created_at": utc_now_iso(),
        "producer": producer,
        "release_ref": release_ref,
    }


def recompute_root_hash(evidence_root: dict) -> str:
    """Recalcula root_hash a partir de artifact_refs -- para verificación
    independiente (¿sigue siendo el mismo conjunto de artefactos?), sin
    confiar en el valor que ya trae el propio dict."""
    refs = [ArtifactRef(**r) for r in evidence_root["artifact_refs"]]
    return _canonical_hash(refs)


def verify_evidence_root(evidence_root: dict) -> bool:
    return recompute_root_hash(evidence_root) == evidence_root["root_hash"]
