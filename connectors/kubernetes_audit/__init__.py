"""Conector Kubernetes Audit — doble rol: fuente de inventario (workload_id,
image_ref, namespace para asset-reconciler) y de telemetría (eventos de
auditoría para normalizer), ver argos-control/architecture/logical/planos.md
(plano P1). Interfaz real; implementación contra la API de auditoría de un
clúster real pendiente de ARG-007/ARG-015.
"""
from __future__ import annotations

from typing import Protocol

from asset_reconciler import AssetFragment
from normalizer import RawEvent


class KubernetesAuditSource(Protocol):
    def fetch_fragments(self) -> list[AssetFragment]: ...

    def fetch_raw_events(self) -> list[RawEvent]: ...


class NotConfiguredKubernetesAuditSource:
    def __init__(self, kubeconfig_path: str):
        self._kubeconfig_path = kubeconfig_path

    def fetch_fragments(self) -> list[AssetFragment]:
        raise NotImplementedError(
            f"Lectura de inventario vía kubeconfig ({self._kubeconfig_path}) "
            "no implementada (ARG-007)."
        )

    def fetch_raw_events(self) -> list[RawEvent]:
        raise NotImplementedError(
            f"Lectura de audit log vía kubeconfig ({self._kubeconfig_path}) "
            "no implementada (ARG-015)."
        )
