"""Conector Hubble (Cilium) — flows de red como RawEvent para normalizer.
Interfaz real; implementación contra la API relay de Hubble pendiente de
ARG-015. Depende de DEP-05 (kernel/eBPF); mismo fallback que connectors/falco/.
"""
from __future__ import annotations

from typing import Protocol

from normalizer import RawEvent


class HubbleSource(Protocol):
    def fetch_raw_events(self) -> list[RawEvent]: ...


class NotConfiguredHubbleSource:
    def __init__(self, relay_endpoint: str):
        self._relay_endpoint = relay_endpoint

    def fetch_raw_events(self) -> list[RawEvent]:
        raise NotImplementedError(
            f"Cliente hacia Hubble relay ({self._relay_endpoint}) no "
            "implementado (ARG-015, DEP-05)."
        )
