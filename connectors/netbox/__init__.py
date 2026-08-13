"""Conector NetBox — fuente de inventario (namespace, node) para
asset-reconciler. Interfaz real; implementación HTTP contra un NetBox real
pendiente de ARG-007 y de credenciales resueltas vía OpenBao
(argos-platform/platform/openbao/) — nunca hardcodeadas aquí.
"""
from __future__ import annotations

from typing import Protocol

from asset_reconciler import AssetFragment


class NetBoxSource(Protocol):
    def fetch_fragments(self) -> list[AssetFragment]: ...


class NotConfiguredNetBoxSource:
    def __init__(self, base_url: str):
        self._base_url = base_url

    def fetch_fragments(self) -> list[AssetFragment]:
        raise NotImplementedError(
            f"Cliente HTTP hacia NetBox ({self._base_url}) no implementado "
            "todavía (ARG-007). Ver connectors/netbox/README.md."
        )
