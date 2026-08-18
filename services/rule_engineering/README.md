# rule_engineering

Compilador determinista `WazuhRuleSpec v1` -> XML de Wazuh + `RuleDeploymentGate` (ADR-069, Fase N).

* **`compile_rule_spec_to_xml`**: función pura, nunca invoca un LLM. `rule_id` se valida contra el rango reservado por Wazuh para reglas custom (100000-120000, `InvalidRuleId` fuera de rango).
* **`RuleDeploymentGate.authorize_deployment`**: fail-closed, exige `SOCDecision.decision == "CONFIRMED_THREAT"`, un `BacktestResult` (`backtest.py`) con volumen aceptable, Y `durable_approval_available=True`. **Este último parámetro es siempre `False` en cualquier llamada real hoy**: `CH-07` (`argos-control/adr/ADR-068-*.md`) confirmó, ejecutando un reinicio real de `mcp_gateway`, que `ApprovalStore` no sobrevive a un reinicio de proceso (`ARG-020` sin cerrar) — hasta que exista un almacén compartido durable, ninguna aprobación SOC de una regla puede desencadenar despliegue automático.

`AI_DIRECT_RULE_DEPLOYMENT = DENY` (ADR-069): el LLM produce `WazuhRuleSpec`, nunca XML.

## Pendiente (ARG-034)

* `backtest.py` opera hoy contra `FakeEventStore` (en memoria) — sin OpenSearch real desplegado, `BLOCKED_EXTERNAL`.
* `wazuh-logtest` (validación de sintaxis contra un binario real de Wazuh) no está integrado — el compilador produce XML bien formado (probado), pero no se ha verificado contra el parser real de Wazuh.
* GitOps de despliegue (canary → activo) no existe todavía — depende de que `durable_approval_available` deje de ser siempre `False`.
