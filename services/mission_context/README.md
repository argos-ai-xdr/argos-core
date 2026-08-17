# mission-context

ADR-060, ADR-051 (Fase K). `MissionContext` + `assess_blast_radius`
(técnico/operacional/de misión), y `evidence.py` (ADR-063) que ancla una
decisión de misión en la infraestructura de evidencia real de Fase J.

**Invariante central, aplicado en código**: `UNKNOWN` nunca es impacto
cero. Sin `MissionContext` para el activo, o con `criticality`/
`crown_jewel` no evaluados, el resultado es `INSUFFICIENT_CONTEXT` —
nunca `NONE`/`LOW` por defecto (ver
`test_no_mission_context_is_insufficient_context_not_none` y afines).

`technical_blast_radius`/`technical_evidence_refs` los suministra el
llamante (el recuento y las referencias reales que produciría
`argos-cyber-tools/graph/blast_radius.py`) — este módulo nunca reimplementa
ese cálculo, solo lo extiende con las capas operacional/misión (K6, no
duplica ARG-011..014).

`assess_blast_radius` nunca decide autorización. `safety_kernel` (ADR-062)
consume `mission_blast_radius` como un hecho más de sus 14
comprobaciones, nunca como el que aprueba.
