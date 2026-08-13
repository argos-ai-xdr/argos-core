# normalizer

Único punto de entrada a `SecurityEvent` (ADR-001). Valida el resultado contra `argos-contracts-scenarios/schemas/security-event/v1.schema.json` antes de devolverlo — nunca produce un evento que no pasaría ese schema.

* **Dedup**: por `(source, native_ref)`, en memoria (instancia de `Normalizer`). Un evento rechazado no consume el dedup (se puede reintentar).
* **Severidad**: conserva `severity_native` y añade `severity_normalized` (regla 6.5.1). El mapeo Wazuh (niveles 0-15) y Falco (prioridad textual) está documentado en el código; una fuente sin regla conocida cae en `"medium"` en vez de asumir `"low"` silenciosamente.
* **Pendiente**: consumir de `argos_events` en vez de recibir `RawEvent` por llamada directa (ARG-015, cuando exista NATS real).
