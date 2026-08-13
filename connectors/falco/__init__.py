"""Conector Falco — alimenta normalizer.Normalizer con RawEvent (severidad
nativa = prioridad textual de Falco, ver normalizer.normalize_severity).
Interfaz real; implementación contra el output de Falco en el clúster
pendiente de ARG-015. Depende de DEP-05 (kernel/eBPF y privilegios); si no
está disponible, el fallback documentado es audit logs + Wazuh/Suricata.
"""
from __future__ import annotations

from typing import Protocol

from normalizer import RawEvent


class FalcoSource(Protocol):
    def fetch_raw_events(self) -> list[RawEvent]: ...


class NotConfiguredFalcoSource:
    def __init__(self, output_endpoint: str):
        self._output_endpoint = output_endpoint

    def fetch_raw_events(self) -> list[RawEvent]:
        raise NotImplementedError(
            f"Suscripción al output de Falco ({self._output_endpoint}) no "
            "implementada (ARG-015, DEP-05)."
        )
