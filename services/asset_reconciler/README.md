# asset-reconciler

Fusiona `AssetFragment` de varias fuentes (NetBox, CMAM, Kubernetes Audit) en un `AssetSnapshot` por `asset_id`. Si dos fuentes discrepan sobre el mismo campo, `reconcile()` lo reporta como conflicto explícito en vez de que la última fuente gane en silencio. `detect_drift` compara as-designed vs. as-built campo a campo (real, no un placeholder).

Sin dato de criticidad, el snapshot usa `"medium"` por defecto (mismo criterio conservador que `risk_engine`), nunca `"low"` a ciegas.
