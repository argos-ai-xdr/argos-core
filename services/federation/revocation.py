"""federation.revocation: registro real de revocación de artefactos
federados (Fase L). Un artefacto previamente aceptado puede volverse
revocado/obsoleto — la única API pública es `revoke`/`is_revoked`/
`revoked_at`, sin método para "des-revocar" (mismo principio de
irreversibilidad que `TransparencyLog`: una revocación es un hecho, no
un estado que se deshace en silencio)."""
from __future__ import annotations


class RevocationRegistry:
    def __init__(self) -> None:
        self._revoked: dict[str, str] = {}
        self._reasons: dict[str, str] = {}

    def revoke(self, artifact_id: str, *, revoked_at: str, reason: str = "") -> None:
        self._revoked[artifact_id] = revoked_at
        self._reasons[artifact_id] = reason

    def is_revoked(self, artifact_id: str) -> bool:
        return artifact_id in self._revoked

    def revoked_at(self, artifact_id: str) -> str | None:
        return self._revoked.get(artifact_id)

    def reason_for(self, artifact_id: str) -> str | None:
        return self._reasons.get(artifact_id)
