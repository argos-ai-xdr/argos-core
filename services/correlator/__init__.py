"""correlator: construye Incident v1 a partir de SecurityEvent (documento
maestro v0.5, servicios principales). Agrupa por asset_id dentro de una
ventana temporal — regla simple y explícita, no un modelo de ML — y separa
explícitamente hecho (member_event_ids, timeline, severity derivada de los
eventos) de inferencia (attack_techniques, confidence).

`attack_techniques` NO se calcula aquí: mapear un evento a una técnica
ATT&CK real requiere las reglas de argos-contracts-scenarios/mappings/attack/
que todavía no existen (ver ese README). Aceptar attack_techniques como
parámetro opcional del llamador es honesto; inventar una técnica plausible
no lo sería (AC08: grounding CTI, inventados = 0).
"""
from __future__ import annotations

import datetime

from argos_envelope import EnvelopeContext, build_envelope, new_id_prefixed
from argos_testing import build_registry, validate_payload

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class InvalidIncident(Exception):
    def __init__(self, errors: list[str]):
        super().__init__(f"Incident inválido: {errors}")
        self.errors = errors


def _parse(observed_at: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(observed_at)  # Python 3.11+ ya entiende el sufijo "Z"


def group_by_asset_and_window(events: list[dict], window: datetime.timedelta) -> list[list[dict]]:
    """Agrupa eventos del mismo asset_id cuya observed_at cae dentro de la
    misma ventana deslizante. Regla determinista: ordena por tiempo y abre
    un grupo nuevo cuando el hueco con el evento anterior del mismo asset
    supera `window` — no es clustering estadístico, es una regla explicable
    (necesaria para el gate G4: "trazabilidad a ground truth")."""
    by_asset: dict[str, list[dict]] = {}
    for event in events:
        asset_id = event.get("asset_id", "unknown")
        by_asset.setdefault(asset_id, []).append(event)

    groups: list[list[dict]] = []
    for asset_events in by_asset.values():
        asset_events.sort(key=lambda e: _parse(e["observed_at"]))
        current_group: list[dict] = []
        last_time: datetime.datetime | None = None
        for event in asset_events:
            event_time = _parse(event["observed_at"])
            if last_time is not None and (event_time - last_time) > window:
                groups.append(current_group)
                current_group = []
            current_group.append(event)
            last_time = event_time
        if current_group:
            groups.append(current_group)
    return groups


def build_incident_payload(
    contracts_path,
    context: EnvelopeContext,
    member_events: list[dict],
    *,
    attack_techniques: list[str] | None = None,
    confidence: str = "low",
) -> dict:
    """confidence por defecto 'low': sin una fuente CTI que la eleve, no se
    afirma más confianza de la justificable (regla de no presentar
    inferencia como hecho)."""
    if not member_events:
        raise ValueError("un Incident necesita al menos un evento miembro")

    incident_id = new_id_prefixed("inc")
    member_event_ids = [e["event_id"] for e in member_events]
    timeline = [
        {"timestamp": e["observed_at"], "description": f"{e['source']}: {e.get('event_id')}"}
        for e in member_events
    ]
    entities = [{"type": "asset", "id": e["asset_id"]} for e in member_events if e.get("asset_id")]
    severity = max(
        (e.get("severity_normalized", "low") for e in member_events),
        key=lambda s: _SEVERITY_ORDER.get(s, 0),
    )
    evidence_refs = [e["id"] for e in member_events]  # referencia al envelope.id de cada evento fuente

    payload = {
        "incident_id": incident_id,
        "member_event_ids": member_event_ids,
        "timeline": timeline,
        "entities": entities,
        "severity": severity,
        "confidence": confidence,
        "evidence_refs": evidence_refs,
    }
    if attack_techniques:
        payload["attack_techniques"] = attack_techniques

    envelope = build_envelope(context, payload, message_id=incident_id)
    full_payload = {**envelope, **payload}

    registry = build_registry(contracts_path)
    errors = validate_payload(contracts_path, registry, "incident", full_payload)
    if errors:
        raise InvalidIncident(errors)
    return full_payload
