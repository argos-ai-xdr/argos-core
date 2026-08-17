"""semantic_conflict: detección y resolución determinista de conflictos
entre fuentes (ADR-061, ADR-051 Fase K; prompt maestro de arquitectura
objetivo, "Semantic Conflict" + "Authority precedence").

**Nunca reasoning generativo.** `resolve_conflict` es una función pura:
mismas claims + misma política de autoridad → misma resolución, siempre.
La clasificación (`TEMPORAL`/`AUTHORITY`/`SEMANTIC`/`CLASSIFICATION`/
`IDENTITY`) la decide el LLAMANTE explícitamente (parámetro), no se
infiere del contenido — qué TIPO de conflicto es algo es un juicio de
dominio, no algo que este módulo deba adivinar.

Regla dura (K5 del prompt): "no escoger automáticamente una versión
salvo que exista una regla determinista de precedencia ya gobernada".
Por eso `resolve_conflict` exige `authority_ranking` explícito — sin él,
no hay política gobernada que aplicar, y el resultado es
`REQUIRES_AUTHORITY`, nunca una elección arbitraria.
"""
from __future__ import annotations

import dataclasses
from typing import Literal

from argos_envelope import new_id_prefixed, utc_now_iso

ConflictClassification = Literal["TEMPORAL", "AUTHORITY", "SEMANTIC", "CLASSIFICATION", "IDENTITY"]
ConflictState = Literal["CONSISTENT", "CONFLICT", "UNKNOWN", "REQUIRES_AUTHORITY"]


@dataclasses.dataclass(frozen=True)
class SourceClaim:
    source_id: str
    value: object
    observed_at: str
    evidence_ref: str | None = None


@dataclasses.dataclass(frozen=True)
class SemanticConflict:
    conflict_id: str
    entity_id: str
    attribute: str
    classification: ConflictClassification
    state: ConflictState
    claims: tuple[SourceClaim, ...]
    winning_source: str | None
    rejected_sources: tuple[str, ...]
    rule: str | None
    reason_code: str
    evidence_refs: tuple[str, ...]
    resolved_at: str


def resolve_conflict(
    entity_id: str,
    attribute: str,
    claims: list[SourceClaim],
    *,
    classification: ConflictClassification,
    authority_ranking: dict[str, int] | None = None,
) -> SemanticConflict:
    now = utc_now_iso()
    evidence_refs = tuple(c.evidence_ref for c in claims if c.evidence_ref)

    if not claims:
        return SemanticConflict(
            conflict_id=new_id_prefixed("semcfl"),
            entity_id=entity_id,
            attribute=attribute,
            classification=classification,
            state="UNKNOWN",
            claims=(),
            winning_source=None,
            rejected_sources=(),
            rule=None,
            reason_code="NO_CLAIMS",
            evidence_refs=(),
            resolved_at=now,
        )

    distinct_values = {c.value for c in claims}
    if len(distinct_values) == 1:
        return SemanticConflict(
            conflict_id=new_id_prefixed("semcfl"),
            entity_id=entity_id,
            attribute=attribute,
            classification=classification,
            state="CONSISTENT",
            claims=tuple(claims),
            winning_source=claims[0].source_id,
            rejected_sources=(),
            rule=None,
            reason_code="ALL_SOURCES_AGREE" if len(claims) > 1 else "SINGLE_SOURCE",
            evidence_refs=evidence_refs,
            resolved_at=now,
        )

    # Hay valores distintos: intentar resolver por autoridad, luego por
    # freshness como desempate -- nunca por orden de llegada.
    ranking = authority_ranking or {}
    ranked = [(ranking.get(c.source_id), c) for c in claims]
    if any(r is None for r, _ in ranked):
        return SemanticConflict(
            conflict_id=new_id_prefixed("semcfl"),
            entity_id=entity_id,
            attribute=attribute,
            classification=classification,
            state="REQUIRES_AUTHORITY",
            claims=tuple(claims),
            winning_source=None,
            rejected_sources=tuple(c.source_id for c in claims),
            rule=None,
            reason_code="NO_GOVERNED_AUTHORITY_FOR_SOURCE",
            evidence_refs=evidence_refs,
            resolved_at=now,
        )

    max_rank = max(r for r, _ in ranked)  # type: ignore[type-var]
    top_claims = [c for r, c in ranked if r == max_rank]

    if len(top_claims) == 1:
        winner = top_claims[0]
        return SemanticConflict(
            conflict_id=new_id_prefixed("semcfl"),
            entity_id=entity_id,
            attribute=attribute,
            classification=classification,
            state="CONFLICT",
            claims=tuple(claims),
            winning_source=winner.source_id,
            rejected_sources=tuple(c.source_id for c in claims if c.source_id != winner.source_id),
            rule="authority_precedence",
            reason_code="HIGHEST_AUTHORITY_WINS",
            evidence_refs=evidence_refs,
            resolved_at=now,
        )

    # Empate de autoridad entre 2+ claims con valores distintos: desempate
    # por freshness (observed_at más reciente), solo si es estricto.
    top_values = {c.value for c in top_claims}
    if len(top_values) == 1:
        # Empatados en autoridad pero coinciden en valor -- no es un
        # conflicto real entre los de mayor autoridad.
        winner = top_claims[0]
        return SemanticConflict(
            conflict_id=new_id_prefixed("semcfl"),
            entity_id=entity_id,
            attribute=attribute,
            classification=classification,
            state="CONFLICT",
            claims=tuple(claims),
            winning_source=winner.source_id,
            rejected_sources=tuple(c.source_id for c in claims if c.value != winner.value),
            rule="authority_precedence",
            reason_code="HIGHEST_AUTHORITY_TIER_AGREES",
            evidence_refs=evidence_refs,
            resolved_at=now,
        )

    freshest_time = max(c.observed_at for c in top_claims)
    freshest_claims = [c for c in top_claims if c.observed_at == freshest_time]
    if len(freshest_claims) == 1:
        winner = freshest_claims[0]
        return SemanticConflict(
            conflict_id=new_id_prefixed("semcfl"),
            entity_id=entity_id,
            attribute=attribute,
            classification=classification,
            state="CONFLICT",
            claims=tuple(claims),
            winning_source=winner.source_id,
            rejected_sources=tuple(c.source_id for c in claims if c.source_id != winner.source_id),
            rule="authority_precedence+freshness_tiebreak",
            reason_code="FRESHEST_AMONG_HIGHEST_AUTHORITY",
            evidence_refs=evidence_refs,
            resolved_at=now,
        )

    return SemanticConflict(
        conflict_id=new_id_prefixed("semcfl"),
        entity_id=entity_id,
        attribute=attribute,
        classification=classification,
        state="REQUIRES_AUTHORITY",
        claims=tuple(claims),
        winning_source=None,
        rejected_sources=tuple(c.source_id for c in claims),
        rule=None,
        reason_code="TIED_AUTHORITY_AND_FRESHNESS",
        evidence_refs=evidence_refs,
        resolved_at=now,
    )
