"""Conector CMAM (Configuration Management / Asset Management, según la
documentación autoritativa de argos-control) — fuente de inventario para
asset-reconciler. Interfaz real; implementación pendiente de ARG-007 y de
confirmar el contrato de API de CMAM (DEP-03: "Interfaces CMAM/VMT").

Fallback documentado en DEP-03: si CMAM no está disponible a tiempo, C-06
se mantiene con NetBox/KAudit + Trivy/OpenVAS + fixtures — este conector
puede quedar sin implementar sin bloquear el MVP.
"""
from __future__ import annotations

from typing import Protocol

from asset_reconciler import AssetFragment


class CMAMSource(Protocol):
    def fetch_fragments(self) -> list[AssetFragment]: ...


class NotConfiguredCMAMSource:
    def __init__(self, base_url: str):
        self._base_url = base_url

    def fetch_fragments(self) -> list[AssetFragment]:
        raise NotImplementedError(
            f"Cliente hacia CMAM ({self._base_url}) no implementado (ARG-007, "
            "DEP-03). Fallback: usar connectors/netbox/ + connectors/kubernetes_audit/."
        )
