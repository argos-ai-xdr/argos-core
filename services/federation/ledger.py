"""federation.ledger: anti-replay real para artefactos federados (§17,
Fase L). Mismo patrón que `IdempotencyStore`
(`argos-cyber-tools/executors/__init__.py`) y `ApprovalStore`
(`argos-cyber-tools/policies/approval/__init__.py`): un registro en
memoria de un único proceso (mismo caveat, ARG-020) que distingue
"mismo artefacto visto otra vez" (idempotente) de "mismo artifact_id con
contenido distinto" (conflicto real, nunca silencioso)."""
from __future__ import annotations


class ContentConflict(ValueError):
    """El mismo artifact_id llegó con un content_hash distinto al ya
    registrado -- nunca se resuelve en silencio sustituyendo el valor."""


class FederationLedger:
    def __init__(self) -> None:
        self._seen: dict[str, str] = {}  # artifact_id -> content_hash

    def check_and_record(self, artifact_id: str, content_hash: str) -> bool:
        """Devuelve True si es la primera vez que se ve este artifact_id
        (o si ya se vio con el MISMO hash -- reintento idempotente).
        Lanza `ContentConflict` si el mismo artifact_id trae un hash
        distinto al ya registrado."""
        existing = self._seen.get(artifact_id)
        if existing is None:
            self._seen[artifact_id] = content_hash
            return True
        if existing != content_hash:
            raise ContentConflict(f"artifact_id {artifact_id!r} ya visto con content_hash {existing!r}, ahora llega con {content_hash!r}")
        return True  # mismo artefacto, mismo contenido: idempotente

    def already_seen(self, artifact_id: str, content_hash: str) -> bool:
        return self._seen.get(artifact_id) == content_hash
