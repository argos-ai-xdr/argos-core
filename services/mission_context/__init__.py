"""mission_context: MissionContext determinista y clasificación de blast
radius técnico/operacional/de misión (ADR-060, ADR-051 Fase K; prompt
maestro de arquitectura objetivo, "Mission Context").

**Invariante central, aplicado en código, no solo documentado**: un
impacto de misión `UNKNOWN` NUNCA se trata como impacto cero. Si falta
contexto crítico (no hay `MissionContext` para el activo, o su
`crown_jewel`/`criticality` es `None`), el resultado es
`INSUFFICIENT_CONTEXT` -- nunca `NONE` ni `LOW` por defecto. Esto es lo
que impide que un activo sin `MissionContext` registrado parezca "sin
impacto de misión" cuando en realidad es "no evaluado".

MissionContext nunca decide autorización -- ver `safety_kernel`, que lo
consume como uno más de los 14 hechos de entrada, nunca como el que
aprueba.
"""
from __future__ import annotations

import dataclasses
from typing import Literal

from argos_envelope import new_id_prefixed, utc_now_iso

MissionImpactLevel = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "INSUFFICIENT_CONTEXT"]


@dataclasses.dataclass(frozen=True)
class MissionContext:
    mission_context_id: str
    entity_id: str
    criticality: str | None  # low|medium|high|critical, None = no evaluado
    crown_jewel: bool | None  # None = no evaluado (nunca se asume False)
    acceptable_degradation: str | None
    maximum_outage: str | None
    recovery_priority: int | None
    dependencies: tuple[str, ...]
    source_id: str
    observed_at: str
    valid_from: str
    valid_until: str | None

    @property
    def has_sufficient_context(self) -> bool:
        return self.criticality is not None and self.crown_jewel is not None


def build_mission_context(
    entity_id: str,
    *,
    source_id: str,
    criticality: str | None = None,
    crown_jewel: bool | None = None,
    acceptable_degradation: str | None = None,
    maximum_outage: str | None = None,
    recovery_priority: int | None = None,
    dependencies: tuple[str, ...] = (),
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> MissionContext:
    now = utc_now_iso()
    return MissionContext(
        mission_context_id=new_id_prefixed("msnctx"),
        entity_id=entity_id,
        criticality=criticality,
        crown_jewel=crown_jewel,
        acceptable_degradation=acceptable_degradation,
        maximum_outage=maximum_outage,
        recovery_priority=recovery_priority,
        dependencies=dependencies,
        source_id=source_id,
        observed_at=now,
        valid_from=valid_from or now,
        valid_until=valid_until,
    )


@dataclasses.dataclass(frozen=True)
class BlastRadiusAssessment:
    technical_blast_radius: int | None  # recuento real (de graph.blast_radius, suministrado por el llamante)
    operational_blast_radius: MissionImpactLevel
    mission_blast_radius: MissionImpactLevel
    reason: str
    technical_evidence_refs: tuple[str, ...] = ()  # NetworkPolicy/RoleBinding examinados -- de graph.blast_radius.BlastRadiusAssessment.evidence_refs, nunca reinventados aquí


_CRITICALITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _operational_level(technical_count: int | None) -> MissionImpactLevel:
    if technical_count is None:
        return "INSUFFICIENT_CONTEXT"
    if technical_count == 0:
        return "NONE"
    if technical_count <= 2:
        return "LOW"
    if technical_count <= 5:
        return "MEDIUM"
    return "HIGH"


def _mission_level(mission_context: MissionContext | None, technical_count: int | None) -> tuple[MissionImpactLevel, str]:
    if mission_context is None:
        return "INSUFFICIENT_CONTEXT", "sin MissionContext registrado para este activo"
    if not mission_context.has_sufficient_context:
        return "INSUFFICIENT_CONTEXT", "MissionContext existe pero criticality/crown_jewel no evaluados"
    if technical_count is None:
        return "INSUFFICIENT_CONTEXT", "blast radius técnico no suministrado"
    if technical_count == 0:
        return "NONE", "sin recursos técnicos afectados"
    if mission_context.crown_jewel:
        return "CRITICAL", "activo crown-jewel con impacto técnico real"
    rank = _CRITICALITY_RANK.get(mission_context.criticality or "", 0)
    if rank >= 3:  # high|critical
        return "HIGH", f"criticality={mission_context.criticality!r} con impacto técnico real"
    if rank == 2:  # medium
        return "MEDIUM", f"criticality={mission_context.criticality!r} con impacto técnico real"
    return "LOW", f"criticality={mission_context.criticality!r} con impacto técnico real"


def assess_blast_radius(
    *,
    mission_context: MissionContext | None,
    technical_affected_count: int | None,
    technical_evidence_refs: tuple[str, ...] = (),
) -> BlastRadiusAssessment:
    """`technical_affected_count`/`technical_evidence_refs`: el recuento y
    las referencias REALES que produciría
    `argos-cyber-tools/graph/blast_radius.py` (`BlastRadiusAssessment.
    evidence_refs`, NetworkPolicy/RoleBinding examinados), suministrados
    por el llamante -- argos-core no importa argos-cyber-tools, mismo
    patrón que `safety_kernel.SafetyCheckInput.observed_blast_radius_count`.
    `None` en el recuento significa "no calculado todavía", nunca "cero"."""
    operational = _operational_level(technical_affected_count)
    mission, reason = _mission_level(mission_context, technical_affected_count)
    return BlastRadiusAssessment(
        technical_blast_radius=technical_affected_count,
        operational_blast_radius=operational,
        mission_blast_radius=mission,
        reason=reason,
        technical_evidence_refs=technical_evidence_refs,
    )
