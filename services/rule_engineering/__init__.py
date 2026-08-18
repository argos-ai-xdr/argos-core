"""rule_engineering: compilador determinista de `WazuhRuleSpec v1` ->
XML de Wazuh, y la puerta de despliegue (ADR-069, Fase N).

**AI_DIRECT_RULE_DEPLOYMENT = DENY** (invariante no negociable, ADR-069):
ningún LLM produce XML de Wazuh directamente. La única entrada que este
módulo acepta es un `WazuhRuleSpec` ya validado contra schema
(`argos-contracts-scenarios/schemas/wazuh-rule-spec`) -- el compilador es
puro y determinista, nunca invoca un modelo, nunca decide si la regla es
buena idea (eso es `RuleDeploymentGate` + el SOC).

`RuleDeploymentGate.authorize_deployment` es el gate final antes de
GitOps -- mismo patrón fail-closed que `mcp_gateway.Gateway.authorize`
(R0-01) y `chaos.ChaosSafetyGuard` (ADR-068): exige, sin excepción,
`SOCDecision.decision == "CONFIRMED_THREAT"`, un `BacktestResult` real
que no exceda el volumen máximo aceptable, Y `durable_approval_available`
explícito. Este último parámetro se mantiene `False` en cualquier
llamada real HOY: `CH-07` (ADR-068) confirmó, ejecutando un reinicio de
verdad, que `ApprovalStore` no sobrevive a un reinicio del proceso
(`ARG-020` sin cerrar) -- hasta que exista un almacén compartido y
durable de aprobaciones, ninguna aprobación SOC de una `RuleCandidate`
puede desencadenar despliegue AUTOMÁTICO, solo generación/validación/
presentación al SOC.
"""
from __future__ import annotations

import dataclasses
import xml.etree.ElementTree as ET

#: Rango reservado por Wazuh para reglas custom (documentación oficial:
#: 100000-120000) -- fuera de este rango, DENY incondicional.
_CUSTOM_RULE_ID_MIN = 100000
_CUSTOM_RULE_ID_MAX = 120000

#: Umbral por defecto de volumen aceptable -- una regla que excede esto
#: no se autoriza aunque el SOC ya la haya marcado CONFIRMED_THREAT
#: (protege contra "10 events/día esperados -> 50.000 alertas/hora
#: reales", ver ADR-069 §10).
_DEFAULT_MAX_ALERTS_PER_HOUR = 100


class InvalidRuleId(Exception):
    pass


def compile_rule_spec_to_xml(rule_spec: dict, *, rule_id: int) -> str:
    """Compilador puro: `WazuhRuleSpec` (dict ya validado contra schema)
    -> XML de Wazuh. `rule_id` se suministra por separado (asignación de
    IDs es responsabilidad operacional del llamante, no de este
    compilador) y se valida contra el rango reservado para reglas
    custom -- fuera de rango, `InvalidRuleId`, nunca un id fabricado."""
    if not (_CUSTOM_RULE_ID_MIN <= rule_id <= _CUSTOM_RULE_ID_MAX):
        raise InvalidRuleId(
            f"rule_id={rule_id} fuera del rango reservado para reglas custom "
            f"({_CUSTOM_RULE_ID_MIN}-{_CUSTOM_RULE_ID_MAX})"
        )

    rule_el = ET.Element("rule", id=str(rule_id), level=str(rule_spec["severity_level"]))

    correlation = rule_spec.get("correlation") or {}
    if correlation.get("frequency"):
        rule_el.set("frequency", str(correlation["frequency"]))
    if correlation.get("timeframe_seconds"):
        rule_el.set("timeframe", str(correlation["timeframe_seconds"]))

    parent_sid = rule_spec.get("parent_rule_sid")
    if parent_sid:
        ET.SubElement(rule_el, "if_matched_sid").text = str(parent_sid)
    if correlation.get("same_source_ip"):
        ET.SubElement(rule_el, "same_source_ip")
    if correlation.get("same_user"):
        ET.SubElement(rule_el, "same_user")

    ET.SubElement(rule_el, "description").text = rule_spec["description"]

    mitre_ids = rule_spec.get("mitre_ids") or []
    if mitre_ids:
        mitre_el = ET.SubElement(rule_el, "mitre")
        for mitre_id in mitre_ids:
            ET.SubElement(mitre_el, "id").text = mitre_id

    groups = rule_spec.get("groups") or []
    if groups:
        ET.SubElement(rule_el, "group").text = ",".join(groups) + ","

    ET.indent(rule_el, space="    ")
    return ET.tostring(rule_el, encoding="unicode")


@dataclasses.dataclass(frozen=True)
class RuleDeploymentAuthorizationResult:
    allowed: bool
    reason: str


class RuleDeploymentGate:
    def __init__(self, *, max_alerts_per_hour: int = _DEFAULT_MAX_ALERTS_PER_HOUR) -> None:
        self._max_alerts_per_hour = max_alerts_per_hour

    def authorize_deployment(
        self,
        *,
        rule_spec: dict,
        soc_decision: dict,
        backtest_result: dict | None,
        durable_approval_available: bool,
    ) -> RuleDeploymentAuthorizationResult:
        if soc_decision.get("decision") != "CONFIRMED_THREAT":
            return RuleDeploymentAuthorizationResult(
                False, f"SOCDecision.decision={soc_decision.get('decision')!r} != CONFIRMED_THREAT"
            )

        if backtest_result is None:
            return RuleDeploymentAuthorizationResult(False, "sin BacktestResult -- ninguna regla se despliega sin backtesting")

        max_alerts = backtest_result.get("max_alerts_per_hour")
        if max_alerts is None or max_alerts > self._max_alerts_per_hour:
            return RuleDeploymentAuthorizationResult(
                False,
                f"max_alerts_per_hour={max_alerts} excede el umbral aceptable ({self._max_alerts_per_hour}) "
                "-- riesgo de tormenta de alertas",
            )

        if not durable_approval_available:
            return RuleDeploymentAuthorizationResult(
                False,
                "AI_DIRECT_RULE_DEPLOYMENT=DENY: sin almacén de aprobación durable (ARG-020 sin cerrar, "
                "CH-07 KNOWN_FAILING, ADR-068) -- generación/validación/presentación al SOC permitidas, "
                "despliegue automático no",
            )

        return RuleDeploymentAuthorizationResult(True, "autorizado")
