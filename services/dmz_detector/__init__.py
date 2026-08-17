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

Propuesta v0.6.25.4 (13.13, Slice P0 y límites de ARG-018) añade
"source_mode correcto" a la aceptación: REAL_CONNECTOR cuando se prueba la
DMZ autorizada, EMULATED cuando se usa replay contractual — nunca se debe
afirmar REAL_CONNECTOR sobre datos de replay. RawEvent (normalizer) es
infraestructura compartida por todos los conectores y no lleva
source_mode; DetectedAnomaly lo transporta junto al RawEvent para que el
llamador lo añada al payload ya validado de SecurityEvent
(additionalProperties: true en el schema — no rompe el contrato).
"""
from __future__ import annotations

import dataclasses

from normalizer import RawEvent

_VALID_SOURCE_MODES = frozenset({"REAL_CONNECTOR", "EMULATED"})


class InvalidSourceMode(Exception):
    pass


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
    source_mode: str  # "REAL_CONNECTOR" | "EMULATED" (propuesta v0.6.25.4, 13.13)


@dataclasses.dataclass(frozen=True)
class Baseline:
    authorized_destinations: frozenset[str]
    max_bytes_per_destination: dict[str, int] = dataclasses.field(default_factory=dict)
    default_max_bytes: int = 1_000_000


@dataclasses.dataclass(frozen=True)
class DetectedAnomaly:
    event: RawEvent
    source_mode: str


def _anomaly_reasons(flow: FlowRecord, baseline: Baseline) -> list[str]:
    reasons = []
    if flow.destination not in baseline.authorized_destinations:
        reasons.append(f"destino no autorizado en baseline: {flow.destination}")
    threshold = baseline.max_bytes_per_destination.get(flow.destination, baseline.default_max_bytes)
    if flow.bytes_transferred > threshold:
        reasons.append(f"volumen {flow.bytes_transferred}B excede baseline {threshold}B (posible exfiltración)")
    return reasons


def detect_anomalies(flows: list[FlowRecord], baseline: Baseline) -> list[DetectedAnomaly]:
    anomalies = []
    for flow in flows:
        if flow.source_mode not in _VALID_SOURCE_MODES:
            raise InvalidSourceMode(
                f"source_mode={flow.source_mode!r} inválido para flow {flow.native_ref!r}, "
                f"debe ser uno de {sorted(_VALID_SOURCE_MODES)}"
            )
        if not _anomaly_reasons(flow, baseline):
            continue
        # externo + no autorizado es lo más grave (exfiltración fuera del
        # perímetro); un destino interno inesperado o un pico de volumen
        # dentro del clúster es serio pero de menor severidad relativa.
        severity = "critical" if flow.destination_is_external else "high"
        anomalies.append(
            DetectedAnomaly(
                event=RawEvent(
                    source="dmz-detector",
                    native_ref=flow.native_ref,
                    severity_native=severity,
                    asset_id=flow.source,
                ),
                source_mode=flow.source_mode,
            )
        )
    return anomalies
