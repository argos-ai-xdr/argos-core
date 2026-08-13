"""Cliente hacia evidence-writer (ADR-006/ADR-016): la única escritura
permitida al evidence store. Otros servicios importan este cliente en vez de
escribir directamente en Ceph RGW/OpenSearch — así la regla "solo
evidence-writer escribe evidencia" es estructural, no solo documental.

InMemoryEvidenceClient es real y suficiente para los tests de otros
servicios; el cliente HTTP/gRPC real hacia services/evidence_writer en
producción es interfaz pendiente (ARG-023, integración end-to-end).
"""
from __future__ import annotations

import dataclasses
from typing import Protocol


class EvidenceClient(Protocol):
    def write_artifact(self, *, run_id: str, media_type: str, content_ref: str, sha256: str) -> str:
        """Devuelve el artifact_id asignado."""
        ...


@dataclasses.dataclass
class InMemoryEvidenceClient:
    """Registra artefactos en memoria; usado por tests de otros servicios
    que necesitan un EvidenceClient real (no un Mock que finge tener la
    interfaz correcta) sin depender de services/evidence_writer desplegado."""

    written: list[dict] = dataclasses.field(default_factory=list)
    _counter: int = 0

    def write_artifact(self, *, run_id: str, media_type: str, content_ref: str, sha256: str) -> str:
        self._counter += 1
        artifact_id = f"artifact-{self._counter}"
        self.written.append(
            {
                "artifact_id": artifact_id,
                "run_id": run_id,
                "media_type": media_type,
                "content_ref": content_ref,
                "sha256": sha256,
            }
        )
        return artifact_id
