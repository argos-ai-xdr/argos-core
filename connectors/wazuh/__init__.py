"""Conector Wazuh — alimenta normalizer.Normalizer con RawEvent (severidad
nativa = rule.level de Wazuh, ver normalizer.normalize_severity). Interfaz
real; implementación contra el indexer/manager de Wazuh
(argos-platform/platform/wazuh/) pendiente de ARG-015.
"""
from __future__ import annotations

from typing import Protocol

from normalizer import RawEvent


class WazuhSource(Protocol):
    def fetch_raw_events(self) -> list[RawEvent]: ...


class NotConfiguredWazuhSource:
    def __init__(self, indexer_url: str):
        self._indexer_url = indexer_url

    def fetch_raw_events(self) -> list[RawEvent]:
        raise NotImplementedError(
            f"Cliente hacia el indexer de Wazuh ({self._indexer_url}) no "
            "implementado (ARG-015)."
        )
