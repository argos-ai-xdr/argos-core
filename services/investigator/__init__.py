"""investigator: ARGOS Global Investigator (ADR-069, Fase N). Escala una
`WeakSignal` (severidad baja, contexto sospechoso) a una investigación
global con expansión de contexto PROGRESIVA y DECLARADA -- nunca
"consultar todo en cada alerta" (ADR-069 §5).

Solo lectura: este módulo decide QUÉ nivel de contexto expandir a
continuación y ENSAMBLA un `ThreatAssessment` a partir de investigation
refs/evidencia ya recopilada -- nunca escribe reglas Wazuh, nunca
modifica OpenSearch, nunca aprueba, nunca ejecuta (misma separación que
`mcp_gateway`: quien investiga/recomienda nunca es quien autoriza ni
ejecuta). La consulta REAL a OpenSearch/Semantic Graph/CTI vive fuera de
este repositorio (`BLOCKED_EXTERNAL` sin esos servicios reales
desplegados) -- este módulo decide el plan, no lo ejecuta él mismo.
"""
from __future__ import annotations

from argos_envelope import EnvelopeContext, build_envelope, new_id_prefixed
from argos_testing import build_registry, validate_payload

#: Orden fijo de expansión de contexto (ADR-069 §5) -- nunca se salta un
#: nivel ni se decide arbitrariamente cuál consultar.
_CONTEXT_LEVELS = ("L0", "L1", "L2", "L3", "L4", "L5")


class InvalidContextLevel(Exception):
    pass


class InvalidThreatAssessment(Exception):
    def __init__(self, errors: list[str]):
        super().__init__(f"ThreatAssessment inválido: {errors}")
        self.errors = errors


def plan_next_context_level(current_level: str | None, *, hypothesis_still_open: bool) -> str | None:
    """Determinista, sin LLM: decide el SIGUIENTE nivel de expansión de
    contexto, o `None` si no hay que seguir escalando.

    `current_level=None` -> siempre `"L0"` (primer paso de cualquier
    investigación). `hypothesis_still_open=False` -> `None` SIEMPRE,
    independientemente del nivel actual -- si la evidencia ya reunida
    resuelve la hipótesis (confirmada o descartada), no hay razón para
    seguir expandiendo contexto, ni siquiera si quedan niveles por
    debajo de L5. Llegar a `"L5"` con la hipótesis todavía abierta
    también devuelve `None` -- L5 es el techo declarado, no hay L6
    implícito."""
    if current_level is None:
        return _CONTEXT_LEVELS[0]
    if current_level not in _CONTEXT_LEVELS:
        raise InvalidContextLevel(f"nivel de contexto desconocido: {current_level!r}")
    if not hypothesis_still_open:
        return None
    index = _CONTEXT_LEVELS.index(current_level)
    if index == len(_CONTEXT_LEVELS) - 1:
        return None
    return _CONTEXT_LEVELS[index + 1]


def build_threat_assessment(
    contracts_path,
    context: EnvelopeContext,
    *,
    investigation_refs: list[str],
    conclusion: str,
    evidence_refs: list[str],
    attack_techniques: list[str] | None = None,
    affected_assets: list[str] | None = None,
    affected_identities: list[str] | None = None,
    mission_impact: str | None = None,
    hypotheses: list[str] | None = None,
    unknowns: list[str] | None = None,
) -> dict:
    """`evidence_refs` obligatorio y no vacío -- un ThreatAssessment sin
    evidencia no es distinto de una opinión (mismo criterio que
    `correlator.build_incident_payload`/`evidence_refs`)."""
    if not investigation_refs:
        raise ValueError("un ThreatAssessment necesita al menos un investigation_ref")
    if not evidence_refs:
        raise ValueError("un ThreatAssessment necesita al menos un evidence_ref")

    assessment_id = new_id_prefixed("assess")
    payload: dict = {
        "assessment_id": assessment_id,
        "investigation_refs": investigation_refs,
        "conclusion": conclusion,
        "evidence_refs": evidence_refs,
    }
    if attack_techniques:
        payload["attack_techniques"] = attack_techniques
    if affected_assets:
        payload["affected_assets"] = affected_assets
    if affected_identities:
        payload["affected_identities"] = affected_identities
    payload["mission_impact"] = mission_impact
    if hypotheses:
        payload["hypotheses"] = hypotheses
    if unknowns:
        payload["unknowns"] = unknowns

    envelope = build_envelope(context, payload, message_id=assessment_id)
    full_payload = {**envelope, **payload}

    registry = build_registry(contracts_path)
    errors = validate_payload(contracts_path, registry, "threat-assessment", full_payload)
    if errors:
        raise InvalidThreatAssessment(errors)
    return full_payload
