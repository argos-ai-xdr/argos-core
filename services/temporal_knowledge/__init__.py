"""temporal_knowledge: reconstrucción determinista de "qué sabía ARGOS
en el momento T" (ADR-059, ADR-051 Fase K; prompt maestro de
arquitectura objetivo, "Temporal Knowledge").

Distinción central, epistémica no ontológica: `query_at(T)` responde
"qué hecho tenía ARGOS registrado y vigente en T", no "qué era cierto en
T". Un hecho con `observed_at > T` NUNCA se devuelve para una consulta
en T, incluso si su `valid_from` sugiere que ya era aplicable entonces
-- ARGOS no podía saberlo todavía. Esta es la propiedad que impide fuga
de información futura (`future_information_leakage = 0`, ver tests).
"""
from __future__ import annotations

import dataclasses

from argos_envelope import new_id_prefixed, utc_now_iso


@dataclasses.dataclass(frozen=True)
class TemporalFact:
    fact_id: str
    entity_id: str
    attribute: str
    value: object
    source_id: str
    observed_at: str
    valid_from: str
    valid_until: str | None
    superseded_at: str | None


def make_fact(
    entity_id: str,
    attribute: str,
    value: object,
    *,
    source_id: str,
    observed_at: str | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> TemporalFact:
    now = observed_at or utc_now_iso()
    return TemporalFact(
        fact_id=new_id_prefixed("fact"),
        entity_id=entity_id,
        attribute=attribute,
        value=value,
        source_id=source_id,
        observed_at=now,
        valid_from=valid_from or now,
        valid_until=valid_until,
        superseded_at=None,
    )


class TemporalKnowledgeBase:
    """Append-only en el mismo sentido que `TransparencyLog`: `add_fact`
    nunca muta un `TemporalFact` existente. `supersede` no reescribe el
    hecho anterior -- registra un `superseded_at` en una COPIA nueva
    dentro de la base y dejar el original tal cual solo tendría sentido
    si además persistiéramos ambas versiones; aquí se modela sustituyendo
    la entrada por su copia con `superseded_at` fijado, preservando el
    resto de campos exactamente -- la vigencia pasada de esa versión
    sigue siendo reconstruible vía `query_at` con un T anterior al
    supersedeo."""

    def __init__(self) -> None:
        self._facts: list[TemporalFact] = []

    def add_fact(self, fact: TemporalFact) -> None:
        self._facts.append(fact)

    def supersede(self, fact_id: str, *, superseded_at: str) -> None:
        for i, fact in enumerate(self._facts):
            if fact.fact_id == fact_id:
                self._facts[i] = dataclasses.replace(fact, superseded_at=superseded_at)
                return
        raise LookupError(f"fact_id {fact_id!r} no existe en esta base")

    def all_facts(self) -> tuple[TemporalFact, ...]:
        return tuple(self._facts)

    def query_at(self, entity_id: str, attribute: str, at_time: str) -> TemporalFact | None:
        """El hecho vigente para (entity_id, attribute) en at_time, o None
        si ninguno cumple. Entre varios candidatos válidos, se devuelve
        el de valid_from más reciente (el hecho más nuevo que YA era
        vigente en at_time) -- determinista, sin ambigüedad."""
        candidates = [
            f
            for f in self._facts
            if f.entity_id == entity_id
            and f.attribute == attribute
            and f.observed_at <= at_time  # ARGOS no pudo saberlo antes de observarlo
            and f.valid_from <= at_time
            and (f.valid_until is None or at_time < f.valid_until)
            and (f.superseded_at is None or at_time < f.superseded_at)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda f: f.valid_from)

    def history_for(self, entity_id: str, attribute: str) -> tuple[TemporalFact, ...]:
        """Todos los hechos alguna vez registrados para (entity_id,
        attribute), en orden de valid_from -- para auditoría, no filtra
        por vigencia."""
        return tuple(
            sorted(
                (f for f in self._facts if f.entity_id == entity_id and f.attribute == attribute),
                key=lambda f: f.valid_from,
            )
        )
