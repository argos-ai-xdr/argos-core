"""semantic_graph: Semantic Cyber Graph determinista (ADR-058, ADR-051
Fase K; prompt maestro de arquitectura objetivo, "Semantic Cyber Graph").

**Nunca genera relaciones con un LLM.** Cada `CyberSemanticEntity`/
`SemanticRelation` se construye a partir de un hecho REAL ya existente en
este proyecto — un `AssetSnapshot`/`VulnerabilityFinding`/`Incident` v1
ya validado, o un hecho RBAC/red que el llamante ya extrajo (p. ej. de
`argos-cyber-tools/graph`, que `argos-core` no puede importar
directamente — mismo patrón de "hechos suministrados por el llamante"
que `safety_kernel.SafetyCheckInput`). No existe ningún "constructor
automático de ontología" en este módulo.

Sin contrato v1 nuevo: nada fuera de `argos-core` consume esto todavía
(mismo criterio que `evidence_root`/`independent_verifier`, ADR-055/057).
"""
from __future__ import annotations

import dataclasses
import hashlib
import json

from argos_envelope import new_id_prefixed, utc_now_iso

#: Tipos mínimos del prompt. Deliberadamente cerrado (no "cualquier
#: string") -- una entidad de tipo no reconocido es un error, no una
#: extensión silenciosa del modelo.
ENTITY_TYPES = frozenset(
    {
        "Asset", "Identity", "Application", "Service", "MissionCapability",
        "MissionObjective", "Vulnerability", "Technique", "Incident",
        "Control", "Policy", "Runbook", "Action",
    }
)

RELATION_TYPES = frozenset({"DEPENDS_ON", "CAN_ACCESS", "AFFECTS", "EXPLOITS", "MITIGATES", "SUPPORTS", "IMPACTS"})


class UnknownEntityType(ValueError):
    pass


class UnknownRelationType(ValueError):
    pass


class DanglingRelation(ValueError):
    """Una relación referencia un entity_id que no está en el grafo -- se
    rechaza en la construcción, nunca se acepta una relación "huérfana"
    silenciosamente."""


@dataclasses.dataclass(frozen=True)
class CyberSemanticEntity:
    entity_id: str
    entity_type: str
    attributes: dict
    source_id: str
    source_type: str
    source_version: str
    observed_at: str
    valid_from: str
    valid_until: str | None
    evidence_ref: str | None
    authority: str

    def content_hash(self) -> str:
        payload = {k: v for k, v in dataclasses.asdict(self).items() if k not in ("observed_at",)}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclasses.dataclass(frozen=True)
class SemanticRelation:
    relation_id: str
    relation_type: str
    source_entity_id: str
    target_entity_id: str
    source_id: str
    source_type: str
    source_version: str
    observed_at: str
    valid_from: str
    valid_until: str | None
    evidence_ref: str | None
    authority: str

    def content_hash(self) -> str:
        payload = {k: v for k, v in dataclasses.asdict(self).items() if k not in ("observed_at",)}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _make_entity(
    entity_type: str,
    attributes: dict,
    *,
    source_id: str,
    source_type: str,
    source_version: str,
    authority: str,
    valid_from: str | None = None,
    valid_until: str | None = None,
    evidence_ref: str | None = None,
) -> CyberSemanticEntity:
    if entity_type not in ENTITY_TYPES:
        raise UnknownEntityType(f"{entity_type!r} no es un tipo de entidad soportado: {sorted(ENTITY_TYPES)}")
    now = utc_now_iso()
    return CyberSemanticEntity(
        entity_id=new_id_prefixed("sement"),
        entity_type=entity_type,
        attributes=attributes,
        source_id=source_id,
        source_type=source_type,
        source_version=source_version,
        observed_at=now,
        valid_from=valid_from or now,
        valid_until=valid_until,
        evidence_ref=evidence_ref,
        authority=authority,
    )


def entity_from_asset_snapshot(
    asset_snapshot: dict,
    *,
    source_type: str,
    source_version: str,
    authority: str,
    evidence_ref: str | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> CyberSemanticEntity:
    """AssetSnapshot v1 (contrato real, argos-contracts-scenarios) ->
    entidad Asset. `source_id` es el propio `producer` del envelope --
    nunca se inventa una procedencia distinta de la que el contrato ya
    declara."""
    return _make_entity(
        "Asset",
        {
            "asset_id": asset_snapshot["asset_id"],
            "workload_id": asset_snapshot.get("workload_id"),
            "namespace": asset_snapshot.get("namespace"),
            "criticality_esp": asset_snapshot.get("criticality_esp"),
        },
        source_id=asset_snapshot["producer"],
        source_type=source_type,
        source_version=source_version,
        authority=authority,
        evidence_ref=evidence_ref,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def entity_from_vulnerability_finding(
    finding: dict,
    *,
    source_type: str,
    source_version: str,
    authority: str,
    evidence_ref: str | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> CyberSemanticEntity:
    return _make_entity(
        "Vulnerability",
        {k: finding.get(k) for k in ("cve_id", "purl", "severity") if k in finding},
        source_id=finding["producer"],
        source_type=source_type,
        source_version=source_version,
        authority=authority,
        evidence_ref=evidence_ref,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def entity_from_incident(
    incident: dict,
    *,
    source_type: str,
    source_version: str,
    authority: str,
    evidence_ref: str | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> CyberSemanticEntity:
    return _make_entity(
        "Incident",
        {"incident_id": incident["incident_id"], "severity": incident.get("severity")},
        source_id=incident["producer"],
        source_type=source_type,
        source_version=source_version,
        authority=authority,
        evidence_ref=evidence_ref,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def _make_relation(
    relation_type: str,
    source_entity_id: str,
    target_entity_id: str,
    *,
    source_id: str,
    source_type: str,
    source_version: str,
    authority: str,
    valid_from: str | None = None,
    valid_until: str | None = None,
    evidence_ref: str | None = None,
) -> SemanticRelation:
    if relation_type not in RELATION_TYPES:
        raise UnknownRelationType(f"{relation_type!r} no es un tipo de relación soportado: {sorted(RELATION_TYPES)}")
    now = utc_now_iso()
    return SemanticRelation(
        relation_id=new_id_prefixed("semrel"),
        relation_type=relation_type,
        source_entity_id=source_entity_id,
        target_entity_id=target_entity_id,
        source_id=source_id,
        source_type=source_type,
        source_version=source_version,
        observed_at=now,
        valid_from=valid_from or now,
        valid_until=valid_until,
        evidence_ref=evidence_ref,
        authority=authority,
    )


@dataclasses.dataclass
class SemanticGraph:
    """Contenedor real: valida en construcción que ninguna relación
    referencia un entity_id ausente -- 'no generar relaciones implícitas'
    también significa 'no aceptar una relación sin ambos extremos
    reales'."""

    entities: dict[str, CyberSemanticEntity] = dataclasses.field(default_factory=dict)
    relations: list[SemanticRelation] = dataclasses.field(default_factory=list)

    def add_entity(self, entity: CyberSemanticEntity) -> None:
        self.entities[entity.entity_id] = entity

    def add_relation(self, relation: SemanticRelation) -> None:
        if relation.source_entity_id not in self.entities:
            raise DanglingRelation(f"relación {relation.relation_id}: source_entity_id {relation.source_entity_id!r} no existe en el grafo")
        if relation.target_entity_id not in self.entities:
            raise DanglingRelation(f"relación {relation.relation_id}: target_entity_id {relation.target_entity_id!r} no existe en el grafo")
        self.relations.append(relation)

    def entities_by_type(self, entity_type: str) -> tuple[CyberSemanticEntity, ...]:
        return tuple(e for e in self.entities.values() if e.entity_type == entity_type)

    def relations_by_type(self, relation_type: str) -> tuple[SemanticRelation, ...]:
        return tuple(r for r in self.relations if r.relation_type == relation_type)

    def relations_for_entity(self, entity_id: str) -> tuple[SemanticRelation, ...]:
        return tuple(r for r in self.relations if r.source_entity_id == entity_id or r.target_entity_id == entity_id)

    def snapshot_hash(self) -> str:
        """Hash determinista del grafo completo -- mismo patrón que
        evidence_root.build_evidence_root: ordenado por content_hash,
        orden de inserción irrelevante."""
        entity_hashes = sorted(e.content_hash() for e in self.entities.values())
        relation_hashes = sorted(r.content_hash() for r in self.relations)
        canonical = json.dumps({"entities": entity_hashes, "relations": relation_hashes}, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def relation_depends_on(graph: SemanticGraph, source_entity_id: str, target_entity_id: str, **kwargs: object) -> SemanticRelation:
    rel = _make_relation("DEPENDS_ON", source_entity_id, target_entity_id, **kwargs)  # type: ignore[arg-type]
    graph.add_relation(rel)
    return rel


def relation_can_access(graph: SemanticGraph, source_entity_id: str, target_entity_id: str, **kwargs: object) -> SemanticRelation:
    rel = _make_relation("CAN_ACCESS", source_entity_id, target_entity_id, **kwargs)  # type: ignore[arg-type]
    graph.add_relation(rel)
    return rel


def relation_affects(graph: SemanticGraph, source_entity_id: str, target_entity_id: str, **kwargs: object) -> SemanticRelation:
    rel = _make_relation("AFFECTS", source_entity_id, target_entity_id, **kwargs)  # type: ignore[arg-type]
    graph.add_relation(rel)
    return rel


def relation_exploits(graph: SemanticGraph, source_entity_id: str, target_entity_id: str, **kwargs: object) -> SemanticRelation:
    rel = _make_relation("EXPLOITS", source_entity_id, target_entity_id, **kwargs)  # type: ignore[arg-type]
    graph.add_relation(rel)
    return rel


def relation_mitigates(graph: SemanticGraph, source_entity_id: str, target_entity_id: str, **kwargs: object) -> SemanticRelation:
    rel = _make_relation("MITIGATES", source_entity_id, target_entity_id, **kwargs)  # type: ignore[arg-type]
    graph.add_relation(rel)
    return rel


def relation_supports(graph: SemanticGraph, source_entity_id: str, target_entity_id: str, **kwargs: object) -> SemanticRelation:
    rel = _make_relation("SUPPORTS", source_entity_id, target_entity_id, **kwargs)  # type: ignore[arg-type]
    graph.add_relation(rel)
    return rel


def relation_impacts(graph: SemanticGraph, source_entity_id: str, target_entity_id: str, **kwargs: object) -> SemanticRelation:
    rel = _make_relation("IMPACTS", source_entity_id, target_entity_id, **kwargs)  # type: ignore[arg-type]
    graph.add_relation(rel)
    return rel
