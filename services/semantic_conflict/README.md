# semantic-conflict

ADR-061, ADR-051 (Fase K). `resolve_conflict` es una función pura y
determinista: mismas claims + misma política de autoridad → misma
resolución, siempre. Nunca reasoning generativo.

Regla dura (K5 del prompt): sin `authority_ranking` gobernado, el
resultado es `REQUIRES_AUTHORITY` — nunca se elige una fuente
arbitrariamente. Con política: autoridad estricta gana; empate de
autoridad se desempata por freshness (`observed_at` más reciente); si
también empata, sigue siendo `REQUIRES_AUTHORITY`.

`asset_reconciler.reconcile()` (ARG-010) se EXTIENDE (no duplica) con un
parámetro `authority_ranking` opcional que usa esta política en vez de
"última fuente gana" — sin él, el comportamiento original no cambia.
