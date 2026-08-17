# semantic-graph

ADR-058, ADR-051 (Fase K). `CyberSemanticEntity`/`SemanticRelation`
reales, construidos SOLO desde hechos ya validados de este proyecto
(`AssetSnapshot`, `VulnerabilityFinding`, `Incident` v1) o hechos
RBAC/red suministrados por el llamante — nunca generados por un LLM.

`SemanticGraph` rechaza relaciones "huérfanas" (`DanglingRelation`) y
expone `snapshot_hash()` determinista (mismo mecanismo de hash agregado
que `evidence_root`) para poder anclar "qué grafo exacto produjo esta
decisión" en la evidencia (ver `mission_context/evidence.py`).

Sin contrato v1 nuevo — nada fuera de `argos-core` lo consume todavía
(mismo criterio que `evidence_root`/`independent_verifier`).
