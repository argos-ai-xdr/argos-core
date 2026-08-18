# investigator

ARGOS Global Investigator (ADR-069, Fase N): escala una `WeakSignal` a una investigación con expansión de contexto progresiva y declarada (L0-L5) — nunca "consultar todo en cada alerta".

* **`plan_next_context_level`**: determinista, sin LLM. `current_level=None` → siempre `"L0"`. `hypothesis_still_open=False` → `None` en cualquier nivel (hipótesis resuelta, dejar de escalar). `"L5"` es el techo declarado — nunca hay `L6` implícito.
* **`build_threat_assessment`**: ensambla un `ThreatAssessment v1` a partir de `investigation_refs`/`evidence_refs` ya recopilados — `ValueError` si cualquiera de los dos está vacío (un `ThreatAssessment` sin evidencia no es distinto de una opinión).

Solo lectura, nunca escritura fuera de `InvestigationRecord`/`ThreatAssessment`: este módulo no escribe reglas Wazuh, no modifica OpenSearch, no aprueba, no ejecuta — misma separación que `mcp_gateway` (quien investiga/recomienda nunca es quien autoriza ni ejecuta).

## Pendiente (ARG-035)

* La consulta REAL a cada nivel (OpenSearch alerts/archives, Semantic Graph, MissionContext, CTI) no existe todavía — este módulo decide el PLAN (`plan_next_context_level`), no ejecuta las consultas él mismo (`BLOCKED_EXTERNAL`, sin esos servicios reales desplegados).
* No hay integración con `argos-cyber-tools/graph` (Semantic Graph real) todavía — `L3` está declarado en el contrato pero no implementado como consulta real.
