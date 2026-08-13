"""soc-adapter: construye SOCHandover v1 y lo filtra por TLP (documento
maestro v0.5, 5.5/5.8: "TLP, allowlist de campos y comprobación automática de
campos prohibidos").

Los campos REQUERIDOS del schema (case_id, incident_summary, timeline,
assets, residual_risk, evidence_manifest_ref, tlp) nunca se eliminan —
quitarlos rompería la validación de schema. El filtrado por TLP actúa sobre
contenido sensible dentro de esos campos (se generaliza/vacía) y sobre los
campos OPCIONALES (iocs, attack_techniques, actions), que sí se pueden
omitir por completo en los niveles más restrictivos.
"""
from __future__ import annotations

from argos_envelope import EnvelopeContext, build_envelope, new_id_prefixed
from argos_testing import build_registry, validate_payload

_REDACTED_SUMMARY = "Resumen redactado por nivel TLP — ver canal autorizado para detalle completo."

# Qué campos opcionales se conservan por nivel. RED es el más restrictivo.
_OPTIONAL_FIELDS_ALLOWED = {
    "RED": set(),
    "AMBER": {"actions"},
    "GREEN": {"actions", "attack_techniques"},
    "CLEAR": {"actions", "attack_techniques", "iocs"},
}


class InvalidHandover(Exception):
    def __init__(self, errors: list[str]):
        super().__init__(f"SOCHandover inválido: {errors}")
        self.errors = errors


def redact_for_tlp(payload: dict, tlp: str) -> dict:
    """Devuelve una copia redactada — nunca muta `payload` (el original,
    sin redactar, es el que debe quedar en el evidence store; solo la copia
    exportada se filtra)."""
    if tlp not in _OPTIONAL_FIELDS_ALLOWED:
        raise ValueError(f"TLP desconocido: {tlp!r}")

    allowed_optional = _OPTIONAL_FIELDS_ALLOWED[tlp]
    redacted = dict(payload)
    for optional_field in ("actions", "attack_techniques", "iocs"):
        if optional_field not in allowed_optional:
            redacted.pop(optional_field, None)

    if tlp == "RED":
        redacted["incident_summary"] = _REDACTED_SUMMARY
        redacted["timeline"] = [{**entry, "description": ""} for entry in redacted.get("timeline", [])]

    return redacted


class SOCAdapter:
    def __init__(self, contracts_path, context: EnvelopeContext):
        self._contracts_path = contracts_path
        self._registry = build_registry(contracts_path)
        self._context = context

    def build_handover(
        self,
        *,
        incident: dict,
        residual_risk: str,
        evidence_manifest_ref: str,
        tlp: str,
        iocs: list[str] | None = None,
        actions: list[str] | None = None,
    ) -> dict:
        case_id = new_id_prefixed("case")
        payload = {
            "case_id": case_id,
            "incident_summary": f"Incidente {incident['incident_id']}, severidad {incident.get('severity', 'desconocida')}",
            "timeline": incident.get("timeline", []),
            "assets": [e["id"] for e in incident.get("entities", []) if e.get("type") == "asset"],
            "residual_risk": residual_risk,
            "evidence_manifest_ref": evidence_manifest_ref,
            "tlp": tlp,
        }
        if incident.get("attack_techniques"):
            payload["attack_techniques"] = incident["attack_techniques"]
        if iocs:
            payload["iocs"] = iocs
        if actions:
            payload["actions"] = actions

        envelope = build_envelope(self._context, payload, message_id=case_id)
        full_payload = {**envelope, **payload}

        errors = validate_payload(self._contracts_path, self._registry, "soc-handover", full_payload)
        if errors:
            raise InvalidHandover(errors)
        return full_payload
