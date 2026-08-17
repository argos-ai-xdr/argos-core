# temporal-knowledge

ADR-059, ADR-051 (Fase K). `TemporalKnowledgeBase.query_at(entity_id,
attribute, T)` reconstruye "qué sabía ARGOS en el momento T" —
epistémico, no ontológico: un hecho con `observed_at > T` nunca se
devuelve, aunque su `valid_from` sugiera que ya aplicaba (`future
information leakage = 0`, ver tests).

`supersede()` nunca borra ni reescribe un hecho anterior — marca
`superseded_at` en una copia, preservando la reconstrucción histórica
para cualquier T anterior al supersedeo. Sin método de borrado en la API
pública (mismo principio que `TransparencyLog`).
