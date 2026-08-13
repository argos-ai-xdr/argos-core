# risk-engine

Ranking explicable de `VulnerabilityFinding` (EPSS × multiplicador KEV × peso de criticidad del activo × descuento por fix disponible). Cada `RiskScore.explanation` expone los factores usados y su procedencia (`source_ref`, `criticality_source_asset_id`) — gate G2: "ranking explica hechos, fuentes y hashes; sin inferencias falsas".

Un finding cuyo `asset_id` no está en el diccionario de activos se penaliza explícitamente (`_UNKNOWN_CRITICALITY_WEIGHT`), nunca se descarta ni se asume `"low"` en silencio.
