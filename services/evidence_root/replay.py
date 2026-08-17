"""replay: reconstrucción y verificación de un run a partir de
`run_id` + `EvidenceManifest`(s) + `EvidenceRoot` + entradas de
`TransparencyLog` (ADR-023, ADR-017 Fase J; prompt maestro de
arquitectura objetivo, "Replay y reconstrucción").

Determinista, no generativo: nunca infiere qué "probablemente" pasó,
solo confirma o refuta con hashes reales recomputados.

Orden de comprobación (un `ReplayResult` solo tiene un `state`, la
primera comprobación que falla decide cuál):
1. `BROKEN_CHAIN` -- la cadena de transparencia en sí ya no es íntegra;
   ninguna comprobación posterior sería fiable sobre una cadena rota.
2. `HASH_MISMATCH` (auto-consistencia) -- el EvidenceRoot no coincide
   con sus propios `artifact_refs`.
3. `MISSING_ARTIFACT` -- un manifiesto real no está representado en el
   EvidenceRoot (o viceversa).
4. `HASH_MISMATCH` (contenido real) -- si se aportan los bytes reales de
   un artefacto, su sha256 recomputado no coincide con el manifiesto.
5. `INCOMPLETE` -- faltan tipos de evento mínimos en la transparencia
   para este `run_id`.
6. `VERIFIED` -- todas las comprobaciones anteriores pasaron.
"""
from __future__ import annotations

import dataclasses
import hashlib
from typing import Literal

from evidence_root import verify_evidence_root
from evidence_root.transparency_log import TransparencyLog

ReplayState = Literal["VERIFIED", "INCOMPLETE", "HASH_MISMATCH", "BROKEN_CHAIN", "MISSING_ARTIFACT"]

#: Mínimo de eventos que cualquier run reconstruible debe tener -- si el
#: llamante necesita exigir más (p. ej. ACTION_ROLLED_BACK cuando hubo
#: rollback), lo pasa explícitamente vía `required_event_types`.
DEFAULT_REQUIRED_EVENT_TYPES = frozenset({"EVIDENCE_ROOT_CREATED"})


@dataclasses.dataclass(frozen=True)
class ReplayResult:
    state: ReplayState
    detail: str

    @property
    def ok(self) -> bool:
        return self.state == "VERIFIED"


def replay_and_verify(
    *,
    run_id: str,
    manifests: list[dict],
    evidence_root: dict,
    log: TransparencyLog,
    artifact_bytes_by_id: dict[str, bytes] | None = None,
    required_event_types: frozenset[str] = DEFAULT_REQUIRED_EVENT_TYPES,
) -> ReplayResult:
    chain_result = log.verify_chain()
    if not chain_result.ok:
        return ReplayResult("BROKEN_CHAIN", chain_result.detail)

    if not verify_evidence_root(evidence_root):
        return ReplayResult("HASH_MISMATCH", "evidence_root no coincide con sus propios artifact_refs (auto-consistencia)")

    root_ids = {r["artifact_id"] for r in evidence_root["artifact_refs"]}
    manifest_by_id = {m["artifact_id"]: m for m in manifests if m}
    missing_in_root = sorted(set(manifest_by_id) - root_ids)
    if missing_in_root:
        return ReplayResult("MISSING_ARTIFACT", f"manifiestos sin representar en evidence_root: {missing_in_root}")
    missing_manifests = sorted(root_ids - set(manifest_by_id))
    if missing_manifests:
        return ReplayResult("MISSING_ARTIFACT", f"artifact_refs del evidence_root sin manifiesto real correspondiente: {missing_manifests}")

    if artifact_bytes_by_id:
        for artifact_id, content in artifact_bytes_by_id.items():
            manifest = manifest_by_id.get(artifact_id)
            if manifest is None:
                return ReplayResult("MISSING_ARTIFACT", f"artifact_id {artifact_id!r} sin manifiesto correspondiente")
            actual = hashlib.sha256(content).hexdigest()
            if actual != manifest["sha256"]:
                return ReplayResult(
                    "HASH_MISMATCH",
                    f"{artifact_id}: sha256 real del contenido ({actual}) != sha256 declarado en el manifiesto ({manifest['sha256']})",
                )

    event_types_seen = {e.event_type for e in log.entries() if e.run_id == run_id}
    missing_events = sorted(required_event_types - event_types_seen)
    if missing_events:
        return ReplayResult("INCOMPLETE", f"eventos de transparencia mínimos ausentes para run_id={run_id!r}: {missing_events}")

    return ReplayResult(
        "VERIFIED",
        "cadena de transparencia íntegra, evidence_root auto-consistente, todos los artefactos representados, eventos mínimos presentes",
    )
