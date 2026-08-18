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

`dedupe_by_correlation_key` (2026-08-18, ARG-015/016): un mismo ataque real
puede producir muchas alertas de la fuente nativa para la misma actividad
-- caso conocido de Falco, que dispara una alerta por cada subproceso Linux
de una misma actividad (correo real del equipo XDR/Wazuh, ver
argos-control/architecture/notes/falco-wazuh-correlation.md). No debemos
convertir cada una en un `Incident` independiente. `correlation_key` es un
hecho suministrado por el llamador (Wazuh puede derivarlo con
`frequency`+`timeframe`+`if_matched_sid`/`if_matched_group` o
`same_source_ip`/`same_user` -- mismo patrón "caller-supplied facts" que
`safety_envelope` en argos-cyber-tools) -- este módulo NO inventa ninguna
regla de qué cuenta como "la misma actividad", solo colapsa lo que ya
llega marcado como tal, preservando cada evento original en
`related_event_refs` para que la evidencia siga siendo auditable
(AC08: nunca perder procedencia al agregar).
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


def dedupe_by_correlation_key(events: list[dict]) -> list[dict]:
    """Colapsa eventos que comparten `correlation.correlation_key` en un
    único evento representativo por clave -- conserva el evento MÁS
    ANTIGUO de cada grupo como base (su `observed_at` real, no uno
    fabricado) y le añade/actualiza `correlation.occurrence_count`,
    `correlation.first_seen`, `correlation.last_seen` y
    `correlation.related_event_refs` (los `id` de envelope de TODOS los
    eventos del grupo, base incluida -- nunca se pierde una referencia).
    Eventos sin `correlation_key` (o con `correlation` ausente) pasan sin
    tocar, uno a uno -- no se inventa una clave que el llamador no dio.
    Determinista: mismo orden de entrada -> mismo resultado, y conserva la
    posición de la PRIMERA aparición de cada clave (o de cada evento sin
    clave) -- no agrupa todo lo colapsado al final."""
    grouped: dict[str, list[dict]] = {}
    for event in events:
        key = (event.get("correlation") or {}).get("correlation_key")
        if key:
            grouped.setdefault(key, []).append(event)

    result: list[dict] = []
    emitted_keys: set[str] = set()
    for event in events:
        key = (event.get("correlation") or {}).get("correlation_key")
        if not key:
            result.append(event)
            continue
        if key in emitted_keys:
            continue
        emitted_keys.add(key)
        members = sorted(grouped[key], key=lambda e: _parse(e["observed_at"]))
        base = members[0]
        collapsed_correlation = dict(base.get("correlation") or {})
        collapsed_correlation.update(
            {
                "correlation_key": key,
                "occurrence_count": len(members),
                "first_seen": members[0]["observed_at"],
                "last_seen": members[-1]["observed_at"],
                "related_event_refs": [m["id"] for m in members],
            }
        )
        result.append({**base, "correlation": collapsed_correlation})

    return result


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
    # dict.fromkeys, no una list comprehension directa: group_by_asset_and_window
    # agrupa precisamente por asset_id, así que el caso normal (no el raro)
    # es que TODOS los eventos miembro compartan el mismo asset_id — sin
    # deduplicar, un incidente con 5 eventos del mismo asset listaba esa
    # misma entidad 5 veces (visible en argos-smartops como
    # affected_assets repetido). dict.fromkeys conserva el orden de
    # primera aparición, a diferencia de un set.
    seen_asset_ids = dict.fromkeys(e["asset_id"] for e in member_events if e.get("asset_id"))
    entities = [{"type": "asset", "id": asset_id} for asset_id in seen_asset_ids]
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
