"""federation.transport: interfaz de transporte separada del núcleo de
decisión de Federación (Fase L; prompt maestro de arquitectura objetivo,
§15, "Transport").

Federation Core (`decision.py`, `cross_domain_transfer.py`) nunca
depende de un transporte concreto -- solo de `FederatedArtifact`.
`InProcessTestTransport` es la ÚNICA implementación real hoy, y está
explícitamente etiquetada TEST/LOCAL: entrega en memoria, dentro del
mismo proceso, determinista. **No existe mTLS real, ni endpoint remoto
real, ni peer STIX-TAXII real, ni pasarela cross-domain real.** No hay
un segundo sitio ARGOS con el que probar transporte real, así que
`REAL_TRANSPORT` se reporta como `BLOCKED_EXTERNAL` -- no se fabrica un
peer remoto para simular que existe.
"""
from __future__ import annotations

import dataclasses
from typing import Protocol

from federation.federated_artifact import FederatedArtifact


class FederationTransport(Protocol):
    """Puerto real: cualquier transporte futuro (mTLS real, gateway
    cross-domain real) lo implementaría sin tocar `decision.py` ni
    `cross_domain_transfer.py`."""

    def send(self, artifact: FederatedArtifact, *, destination_instance: str) -> str: ...

    def receive(self) -> tuple[FederatedArtifact, ...]: ...


@dataclasses.dataclass(frozen=True)
class TransportLabel:
    mode: str


class InProcessTestTransport:
    """Transporte determinista en memoria, dentro del MISMO proceso
    Python -- nunca se interpreta como validación de federación
    multi-sitio real. `label.mode` es siempre `"TEST_LOCAL"`, expuesto
    como atributo real (no solo un comentario) para que un test pueda
    afirmar explícitamente que nadie está fingiendo un transporte real."""

    label = TransportLabel(mode="TEST_LOCAL")

    def __init__(self) -> None:
        self._outbox: list[tuple[str, FederatedArtifact]] = []
        self._inbox: list[FederatedArtifact] = []

    def send(self, artifact: FederatedArtifact, *, destination_instance: str) -> str:
        self._outbox.append((destination_instance, artifact))
        self._inbox.append(artifact)
        return artifact.artifact_id

    def receive(self) -> tuple[FederatedArtifact, ...]:
        drained = tuple(self._inbox)
        self._inbox = []
        return drained

    def outbox(self) -> tuple[tuple[str, FederatedArtifact], ...]:
        return tuple(self._outbox)
