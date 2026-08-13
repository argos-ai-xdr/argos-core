"""Interfaz de bus de eventos (ADR-002: NATS JetStream en producción) más una
implementación en memoria real y funcional para tests/integración local, sin
depender de un clúster NATS.

El cliente NATS real (TLS, subjects allowlist, durable consumers, DLQ) no
está implementado todavía — es interfaz pendiente de ARG-015. Usar
InMemoryEventBus para todo lo que no requiera probar contra NATS de verdad.
"""
from __future__ import annotations

import collections
import dataclasses
from collections.abc import Callable
from typing import Protocol


@dataclasses.dataclass(frozen=True)
class Message:
    subject: str
    payload: dict


class EventBus(Protocol):
    def publish(self, subject: str, payload: dict) -> None: ...

    def subscribe(self, subject: str, handler: Callable[[Message], None]) -> None: ...


class InMemoryEventBus:
    """Bus síncrono en memoria: publish entrega inmediatamente a los
    handlers suscritos al subject exacto. No implementa wildcards de NATS
    (`*`, `>`) ni persistencia — suficiente para tests deterministas, no
    para probar la semántica real de JetStream (eso requiere ARG-015 y un
    NATS real, ver argos-platform/platform/nats/)."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[[Message], None]]] = collections.defaultdict(list)
        self.published: list[Message] = []

    def publish(self, subject: str, payload: dict) -> None:
        message = Message(subject=subject, payload=payload)
        self.published.append(message)
        for handler in self._handlers.get(subject, []):
            handler(message)

    def subscribe(self, subject: str, handler: Callable[[Message], None]) -> None:
        self._handlers[subject].append(handler)
