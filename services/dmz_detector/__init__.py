"""dmz-detector: detección de anomalías DMZ/egress basada en reglas +
baseline (ARG-018, C-08.UC5). Analiza FlowRecord (forma de Hubble/firewall
flow) y produce RawEvent — normalizer.Normalizer los convierte en
SecurityEvent reales, reutilizando el pipeline ya existente en vez de
inventar un contrato de salida nuevo (el documento maestro fija 10
contratos v1 cerrados; SecurityEvent ya es el contrato para "señal
detectada por una fuente", que es justo lo que esto es — mismo tratamiento
que Wazuh/Falco en normalizer.normalize_severity).

Un flujo ya bloqueado (verdict=DENIED, contenido por NetworkPolicy) sigue
siendo señal real: un intento de exfiltración contenido no es "sin
anomalía", es una anomalía que además fue contenida. Omitirlo violaría
"anomalía crítica golden omitida = 0" (C-08.UC5) — mismo tipo de fallo ya
encontrado y corregido en evaluators.detection (argos-validation).
"""
from __future__ import annotations

import dataclasses

from normalizer import RawEvent


@dataclasses.dataclass(frozen=True)
class FlowRecord:
    native_ref: str  # referencia al flow original de Hubble/firewall, nunca reescrito (ADR-001)
    source: str  # asset_id/pod de origen
    destination: str  # IP o nombre; ver Baseline.authorized_destinations
    destination_is_external: bool
    port: int
    protocol: str
    bytes_transferred: int
    verdict: str  # "ALLOWED" | "DENIED" — Hubble ya bloqueó DENIED vía NetworkPolicy, pero sigue siendo señal


@dataclasses.dataclass(frozen=True)
class Baseline:
    authorized_destinations: frozenset[str]
    max_bytes_per_destination: dict[str, int] = dataclasses.field(default_factory=dict)
    default_max_bytes: int = 1_000_000


def _anomaly_reasons(flow: FlowRecord, baseline: Baseline) -> list[str]:
    reasons = []
    if flow.destination not in baseline.authorized_destinations:
        reasons.append(f"destino no autorizado en baseline: {flow.destination}")
    threshold = baseline.max_bytes_per_destination.get(flow.destination, baseline.default_max_bytes)
    if flow.bytes_transferred > threshold:
        reasons.append(f"volumen {flow.bytes_transferred}B excede baseline {threshold}B (posible exfiltración)")
    return reasons


def detect_anomalies(flows: list[FlowRecord], baseline: Baseline) -> list[RawEvent]:
    events = []
    for flow in flows:
        if not _anomaly_reasons(flow, baseline):
            continue
        # externo + no autorizado es lo más grave (exfiltración fuera del
        # perímetro); un destino interno inesperado o un pico de volumen
        # dentro del clúster es serio pero de menor severidad relativa.
        severity = "critical" if flow.destination_is_external else "high"
        events.append(
            RawEvent(
                source="dmz-detector",
                native_ref=flow.native_ref,
                severity_native=severity,
                asset_id=flow.source,
            )
        )
    return events
