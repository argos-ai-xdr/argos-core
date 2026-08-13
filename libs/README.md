# libs/

| Paquete | Rol |
| --- | --- |
| [`argos_envelope/`](argos_envelope/) | Construye el envelope común (ADR-001): `build_envelope`, `sha256_of_payload` |
| [`argos_events/`](argos_events/) | Interfaz de bus de eventos + `InMemoryEventBus` real para tests (NATS real pendiente, ARG-015) |
| [`argos_telemetry/`](argos_telemetry/) | Propagación de `run_id`/`trace_id` vía `contextvars` (ADR-009; exporter OTel real pendiente) |
| [`argos_evidence/`](argos_evidence/) | Cliente hacia `evidence_writer` — hace estructural la regla "solo evidence-writer escribe evidencia" |
| [`argos_testing/`](argos_testing/) | Resuelve `argos-contracts-scenarios` y valida payloads contra sus schemas (mismo patrón que `argos-validation/harness/loaders/`) |

Cada uno es real y funcional hoy, no un stub — las partes que dependen de infraestructura no desplegada todavía (NATS, OTel collector, evidence-writer en producción) lo dicen explícitamente en su docstring en vez de fingir estar completas.
