"""Conector VMT (Vulnerability Management Tool, fuente autoritativa de
argos-control) — inventario de vulnerabilidades ya gestionado. Interfaz
real; implementación pendiente de ARG-008 y de DEP-03 ("Interfaces CMAM/VMT",
fecha límite fin de S1).

Fallback documentado en DEP-03: si VMT no está disponible, C-06 se mantiene
con Trivy/OpenVAS directos — este conector puede quedar sin implementar sin
bloquear el MVP.
"""
from __future__ import annotations

from typing import Protocol


class VMTSource(Protocol):
    def fetch_raw_findings(self, *, asset_id: str) -> list[dict]: ...


class NotConfiguredVMTSource:
    def __init__(self, base_url: str):
        self._base_url = base_url

    def fetch_raw_findings(self, *, asset_id: str) -> list[dict]:
        raise NotImplementedError(
            f"Cliente hacia VMT ({self._base_url}) no implementado (ARG-008, "
            "DEP-03). Fallback: connectors/trivy/ + connectors/openvas/."
        )
