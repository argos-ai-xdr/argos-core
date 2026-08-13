"""Conector OpenVAS/Greenbone — hallazgos de escaneo de red/host, misma
forma de salida que trivy (compatible con vulnerability_adapter, adaptando
los nombres de campo GMP a los esperados por normalize_trivy_finding cuando
se implemente un normalize_openvas_finding equivalente). Interfaz real;
implementación pendiente de ARG-008.
"""
from __future__ import annotations

from typing import Protocol


class OpenVASSource(Protocol):
    def fetch_raw_findings(self, *, asset_id: str, target: str) -> list[dict]: ...


class NotConfiguredOpenVASSource:
    def __init__(self, gmp_endpoint: str):
        self._gmp_endpoint = gmp_endpoint

    def fetch_raw_findings(self, *, asset_id: str, target: str) -> list[dict]:
        raise NotImplementedError(
            f"Cliente GMP hacia OpenVAS ({self._gmp_endpoint}) contra "
            f"{target} no implementado (ARG-008)."
        )
