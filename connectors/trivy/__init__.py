"""Conector Trivy — alimenta vulnerability_adapter.normalize_trivy_finding
con hallazgos crudos (forma `trivy image --format json`, simplificada).
Interfaz real; ejecución real de `trivy` (CLI o servidor) pendiente de
ARG-008. La DB de firmas debe congelarse para aceptación (ADR-010/6.4:
"DB de firmas congelada para aceptación") — este conector no decide eso,
solo expone dónde se fija esa versión.
"""
from __future__ import annotations

from typing import Protocol


class TrivySource(Protocol):
    def fetch_raw_findings(self, *, asset_id: str, image_ref: str) -> list[dict]: ...


class NotConfiguredTrivySource:
    def __init__(self, db_version: str):
        self._db_version = db_version  # fijado explícitamente, no "latest"

    def fetch_raw_findings(self, *, asset_id: str, image_ref: str) -> list[dict]:
        raise NotImplementedError(
            f"Ejecución de trivy (db_version={self._db_version}) contra "
            f"{image_ref} no implementada (ARG-008)."
        )
