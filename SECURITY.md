# Política de seguridad — argos-core

Ver la política transversal en `argos-control/SECURITY.md`. Específico de este repositorio:

* `services/recommendation` (LangGraph/vLLM) no tiene credenciales de ejecución ni de aprobación (ADR-005, ADR-008, ADR-011). Un PR que le añada un cliente hacia un ejecutor de `argos-cyber-tools` se rechaza sin un ADR nuevo.
* `services/evidence_writer` es la única escritura permitida al evidence store (`argos-platform/platform/opensearch/`, `ceph-rgw/`); el agente no tiene permisos de modificación sobre evidencia ya escrita (ADR-006).
* `connectors/` nunca almacena credenciales en código ni en `values.yaml` — se resuelven en tiempo de arranque desde OpenBao (`argos-platform/platform/openbao/`).
* Ningún servicio almacena chain-of-thought del modelo en logs, trazas ni `Recommendation.rationale_refs` (ADR-016).

## Reporte

Reportar vulnerabilidades o hallazgos vía el issue template `risk.yaml` o `exception.yaml` de `argos-control`, notificando al rol `qa-security-observer`.
