"""mission_context.evidence: integra Semantic/Mission (Fase K) con la
infraestructura de evidencia ya real de Fase J — ADR-063, ADR-051.

**No crea un mecanismo de evidencia paralelo.** Reutiliza
`evidence_writer.EvidenceWriter` y `evidence_root.build_evidence_root`
tal cual — este módulo solo construye el PAYLOAD (`MissionDecisionRecord`)
que se hashea y ancla con esos mecanismos ya probados en Fase J.

Invariante cruzado K (literal del usuario): un cambio posterior al grafo
semántico o al modelo de misión NO debe reescribir lo que ARGOS sabía en
el momento de la decisión original. Por eso `MissionDecisionRecord` es
un snapshot congelado — `semantic_graph_snapshot_hash`/
`mission_context_hash` son hashes de contenido en el momento de la
decisión, y el `EvidenceManifest`/`EvidenceRoot` que los ancla nunca se
regenera para una decisión ya tomada, solo se construyen otros nuevos
para decisiones nuevas.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json

from argos_envelope import EnvelopeContext, new_id_prefixed, utc_now_iso
from evidence_root import build_evidence_root
from evidence_writer import EvidenceWriter, RetentionPolicy
from semantic_conflict import SemanticConflict
from semantic_graph import SemanticGraph

from mission_context import BlastRadiusAssessment, MissionContext


def _mission_context_hash(mission_context: MissionContext | None) -> str | None:
    if mission_context is None:
        return None
    payload = {k: v for k, v in dataclasses.asdict(mission_context).items() if k not in ("observed_at", "mission_context_id")}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _conflict_to_dict(conflict: SemanticConflict) -> dict:
    return {
        "conflict_id": conflict.conflict_id,
        "entity_id": conflict.entity_id,
        "attribute": conflict.attribute,
        "classification": conflict.classification,
        "state": conflict.state,
        "winning_source": conflict.winning_source,
        "rejected_sources": list(conflict.rejected_sources),
        "rule": conflict.rule,
        "reason_code": conflict.reason_code,
    }


def build_mission_decision_record(
    *,
    entity_id: str,
    semantic_graph: SemanticGraph,
    mission_context: MissionContext | None,
    temporal_query_time: str,
    conflicts: list[SemanticConflict],
    blast_radius: BlastRadiusAssessment,
    safety_kernel_state: str,
    safety_kernel_reason: str,
    unknowns: tuple[str, ...],
) -> dict:
    """Payload puro, serializable -- ninguna llamada de red ni escritura
    de evidencia aquí (eso lo hace `record_mission_decision_evidence`)."""
    source_refs = sorted({e.evidence_ref for e in semantic_graph.entities.values() if e.evidence_ref} | {r.evidence_ref for r in semantic_graph.relations if r.evidence_ref})
    return {
        "record_id": new_id_prefixed("msndec"),
        "entity_id": entity_id,
        "semantic_graph_snapshot_hash": semantic_graph.snapshot_hash(),
        "mission_context_hash": _mission_context_hash(mission_context),
        "temporal_query_time": temporal_query_time,
        "source_refs": source_refs,
        "authority_resolution": [_conflict_to_dict(c) for c in conflicts if c.state == "CONFLICT"],
        "semantic_conflicts": [_conflict_to_dict(c) for c in conflicts],
        "unknowns": list(unknowns),
        "blast_radius_result": {
            "technical_blast_radius": blast_radius.technical_blast_radius,
            "operational_blast_radius": blast_radius.operational_blast_radius,
            "mission_blast_radius": blast_radius.mission_blast_radius,
            "reason": blast_radius.reason,
            "technical_evidence_refs": list(blast_radius.technical_evidence_refs),
        },
        "safety_kernel_state": safety_kernel_state,
        "safety_kernel_reason": safety_kernel_reason,
        "created_at": utc_now_iso(),
    }


@dataclasses.dataclass(frozen=True)
class MissionDecisionEvidence:
    record: dict
    manifest: dict
    evidence_root: dict


def record_mission_decision_evidence(
    record: dict,
    *,
    contracts_path,
    context: EnvelopeContext,
    run_id: str,
) -> MissionDecisionEvidence:
    """Ancla el record con el mecanismo de Fase J tal cual, sin
    duplicarlo: EvidenceWriter hashea el contenido real del record;
    build_evidence_root agrega ese único manifiesto (y cualquier otro
    que el llamante añada) en un root determinista."""
    writer = EvidenceWriter(contracts_path, context)
    content = json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
    manifest = writer.write_bytes(content, media_type="application/json", retention=RetentionPolicy(policy="365d"))
    root = build_evidence_root([manifest], run_id=run_id, producer="mission-decision-record", incident_id=record.get("entity_id"))
    return MissionDecisionEvidence(record=record, manifest=manifest, evidence_root=root)
