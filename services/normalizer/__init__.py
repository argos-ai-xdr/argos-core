"""normalizer: único punto de entrada a SecurityEvent (documento maestro
v0.5, servicios principales — "normalizer"). Valida contra el schema real de
argos-contracts-scenarios, asigna event_id/run_id, deduplica por
(source, native_ref) y normaliza severidad. Rechaza explícitamente lo que no
cumple — nunca deja pasar un evento sin schema_version/native_ref.
"""
from __future__ import annotations

import dataclasses
import pathlib

from argos_envelope import EnvelopeContext, build_envelope, new_id_prefixed
from argos_testing import build_registry, validate_payload

# Umbrales de severidad por fuente — documentados explícitamente porque cada
# fuente tiene su propia escala nativa (Wazuh: rule.level 0-15; Falco:
# prioridad textual). Fuente desconocida usa un fallback conservador (todo
# "medium" salvo que el valor ya sea uno de los 4 normalizados).
_WAZUH_LEVEL_THRESHOLDS = (
    (13, "critical"),
    (10, "high"),
    (7, "medium"),
    (0, "low"),
)

_FALCO_PRIORITY_MAP = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "medium",
    "informational": "low",
    "debug": "low",
}

_NORMALIZED_LEVELS = {"low", "medium", "high", "critical"}


class RejectedEvent(Exception):
    def __init__(self, reason: str, schema_errors: list[str] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.schema_errors = schema_errors or []


def normalize_severity(source: str, severity_native: str) -> str:
    """Devuelve un valor de _NORMALIZED_LEVELS. Regla 6.5.1 del documento
    maestro: "severidad conserva valor nativo y valor normalizado" — este
    normalizador nunca descarta severity_native, solo añade
    severity_normalized."""
    value = severity_native.strip().lower()
    if value in _NORMALIZED_LEVELS:
        return value

    if source == "wazuh":
        try:
            level = int(severity_native)
        except ValueError:
            return "medium"
        for threshold, label in _WAZUH_LEVEL_THRESHOLDS:
            if level >= threshold:
                return label
        return "low"

    if source == "falco" and value in _FALCO_PRIORITY_MAP:
        return _FALCO_PRIORITY_MAP[value]

    return "medium"  # fuente sin regla conocida: no asumir "low" a ciegas


@dataclasses.dataclass(frozen=True)
class RawEvent:
    """Lo que un conector produce, antes de convertirse en SecurityEvent."""

    source: str
    native_ref: str
    severity_native: str
    asset_id: str | None = None
    workload_id: str | None = None


@dataclasses.dataclass(frozen=True)
class NormalizeResult:
    event_id: str
    payload: dict


class Normalizer:
    def __init__(self, contracts_path: pathlib.Path, context: EnvelopeContext):
        self._contracts_path = contracts_path
        self._registry = build_registry(contracts_path)
        self._context = context
        self._seen: set[tuple[str, str]] = set()

    def process(self, raw: RawEvent) -> NormalizeResult:
        dedup_key = (raw.source, raw.native_ref)
        if dedup_key in self._seen:
            raise RejectedEvent(f"duplicado: ya se procesó {dedup_key}")
        self._seen.add(dedup_key)

        event_id = new_id_prefixed("evt")
        payload = {
            "event_id": event_id,
            "source": raw.source,
            "severity_native": raw.severity_native,
            "severity_normalized": normalize_severity(raw.source, raw.severity_native),
        }
        if raw.asset_id:
            payload["asset_id"] = raw.asset_id
        if raw.workload_id:
            payload["workload_id"] = raw.workload_id

        envelope = build_envelope(
            self._context, payload, message_id=event_id, native_ref=raw.native_ref
        )
        full_payload = {**envelope, **payload}

        errors = validate_payload(self._contracts_path, self._registry, "security-event", full_payload)
        if errors:
            self._seen.discard(dedup_key)  # no consumir el dedup por un evento rechazado
            raise RejectedEvent("schema inválido", schema_errors=errors)

        return NormalizeResult(event_id=event_id, payload=full_payload)
