"""Conector MISP — IoCs y técnicas ATT&CK desde snapshots fijados (ADR-007:
sin consultas online durante la ejecución de aceptación). Alimenta
correlator.build_incident_payload(attack_techniques=...) y el grounding de
argos-contracts-scenarios/mappings/attack/.

Interfaz real; lectura de un snapshot MISP real
(argos-contracts-scenarios/snapshots/cti/) pendiente de ARG-016. Nunca debe
consultar la instancia MISP en vivo durante un run de aceptación — solo
snapshots con fecha y hash.
"""
from __future__ import annotations

from typing import Protocol


class MISPSource(Protocol):
    def fetch_iocs(self, *, snapshot_ref: str) -> list[dict]: ...

    def fetch_attack_techniques(self, *, snapshot_ref: str, ioc_ids: list[str]) -> list[str]: ...


class NotConfiguredMISPSource:
    def fetch_iocs(self, *, snapshot_ref: str) -> list[dict]:
        raise NotImplementedError(
            f"Lectura de snapshot MISP ({snapshot_ref}) no implementada "
            "(ARG-016). Ver argos-contracts-scenarios/snapshots/cti/."
        )

    def fetch_attack_techniques(self, *, snapshot_ref: str, ioc_ids: list[str]) -> list[str]:
        raise NotImplementedError(
            f"Resolución de técnicas ATT&CK desde snapshot ({snapshot_ref}) "
            "no implementada (ARG-016)."
        )
