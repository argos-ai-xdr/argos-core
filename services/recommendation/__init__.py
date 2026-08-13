"""recommendation: produce Recommendation v1 a partir de un Incident.

ADR-008: el modelo (LangGraph/vLLM) no decide autorización y debe tener un
fallback determinista que funcione sin LLM. Este módulo implementa ESE
fallback de verdad (reglas por severidad, sin red, sin modelo) y define la
interfaz que implementaría el motor LangGraph real — sin implementarlo,
porque no hay vLLM desplegado en este bootstrap (ADR-008, DEP-06).

El LLM (cuando exista) nunca tiene credenciales de ejecución: solo produce
`Recommendation`, igual que el fallback. Ningún RecommendationEngine debe
importar un cliente de argos-cyber-tools/ejecutores.
"""
from __future__ import annotations

from typing import Protocol

from argos_envelope import EnvelopeContext, build_envelope, new_id_prefixed
from argos_testing import build_registry, validate_payload

# Runbook mínimo por severidad — F07/F08 (documento maestro v0.5, 5.3):
# alternativas reales, no texto de relleno. ARG-019 lo ampliará con más
# runbooks; este es el fallback de línea base, no el catálogo completo.
_RUNBOOK_BY_SEVERITY: dict[str, list[dict]] = {
    "critical": [
        {"action": "isolate_kubernetes_workload", "description": "Aplicar CiliumNetworkPolicy temporal de aislamiento"},
        {"action": "scale_to_zero", "description": "Escalar a cero el deployment afectado"},
    ],
    "high": [
        {"action": "isolate_kubernetes_workload", "description": "Aplicar CiliumNetworkPolicy temporal de aislamiento"},
    ],
    "medium": [
        {"action": "increase_monitoring", "description": "Elevar verbosidad de logging/telemetría del activo afectado"},
    ],
    "low": [
        {"action": "log_only", "description": "Registrar para revisión periódica, sin acción de contención"},
    ],
}


class InvalidRecommendation(Exception):
    def __init__(self, errors: list[str]):
        super().__init__(f"Recommendation inválida: {errors}")
        self.errors = errors


class RecommendationEngine(Protocol):
    def generate(self, incident: dict) -> dict:
        """Devuelve un payload de Recommendation v1 ya validado."""
        ...


class LangGraphEngine:
    """Interfaz documentada, no implementada. Requiere vLLM desplegado
    (argos-platform, DEP-06) y el grafo LangGraph real (ARG-019). Ver
    ADR-008: el LLM no decide autorización; su salida pasa por el mismo
    validate_payload que el fallback determinista, sin excepciones."""

    def generate(self, incident: dict) -> dict:
        raise NotImplementedError(
            "LangGraphEngine requiere vLLM desplegado (DEP-06) y el grafo de "
            "ARG-019; usar DeterministicFallbackEngine mientras tanto (ADR-008)."
        )


class DeterministicFallbackEngine:
    def __init__(self, contracts_path, context: EnvelopeContext):
        self._contracts_path = contracts_path
        self._registry = build_registry(contracts_path)
        self._context = context

    def generate(self, incident: dict) -> dict:
        severity = incident.get("severity", "low")
        alternatives = _RUNBOOK_BY_SEVERITY.get(severity, _RUNBOOK_BY_SEVERITY["low"])

        recommendation_id = new_id_prefixed("reco")
        payload = {
            "recommendation_id": recommendation_id,
            "incident_id": incident["incident_id"],
            "alternatives": alternatives,
            "selected_action": alternatives[0]["action"],
            "rationale_refs": incident.get("evidence_refs", []),
            "impact": f"Fallback determinista para severidad '{severity}'; sin LLM disponible",
            "uncertainty": "alta — decisión por regla fija, no por análisis del incidente concreto",
            "rollback_plan": "Revertir la política/escala aplicada y restaurar el estado previo verificado",
        }
        envelope = build_envelope(self._context, payload, message_id=recommendation_id)
        full_payload = {**envelope, **payload}

        errors = validate_payload(self._contracts_path, self._registry, "recommendation", full_payload)
        if errors:
            raise InvalidRecommendation(errors)
        return full_payload
