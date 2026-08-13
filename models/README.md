# models/

| Carpeta | Contenido |
| --- | --- |
| [`deterministic-fallback/`](deterministic-fallback/) | Runbook de `services/recommendation` en formato de datos (hoy hardcodeado en Python; esta es la versión de referencia hacia la que migrar en ARG-019) |
| [`prompts/`](prompts/) | Plantillas de prompt para el futuro `LangGraphEngine` — ninguna en uso todavía (ADR-008: no hay LLM desplegado) |
| [`structured-output/`](structured-output/) | La salida estructurada que debe producir el LLM ya es el contrato `Recommendation v1` — no se duplica aquí, ver `argos-contracts-scenarios/schemas/recommendation/` |
| [`evaluation-config/`](evaluation-config/) | Qué evalúa `argos-validation` sobre las salidas de este repositorio — no se duplica aquí, ver `argos-validation/suites/` y `thresholds/` |
