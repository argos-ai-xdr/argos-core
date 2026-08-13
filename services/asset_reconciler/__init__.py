"""asset-reconciler: ingiere fragmentos de inventario de varias fuentes
(NetBox, CMAM, Kubernetes Audit) y los reconcilia en un único AssetSnapshot;
detecta drift entre el estado as-designed y el as-built (documento maestro
v0.5, servicios principales).

Cada conector produce solo lo que sabe (NetBox: namespace/node; Kubernetes
Audit: workload_id/image_ref) — reconcile() los fusiona y, si dos fuentes
DISCREPAN sobre el mismo campo, lo reporta como conflicto en vez de que una
fuente sobrescriba a la otra en silencio.
"""
from __future__ import annotations

import dataclasses

from argos_envelope import EnvelopeContext, build_envelope, new_id_prefixed
from argos_testing import build_registry, validate_payload

_MERGEABLE_FIELDS = ("workload_id", "image_ref", "node", "namespace", "criticality_esp")


class InvalidAssetSnapshot(Exception):
    def __init__(self, errors: list[str]):
        super().__init__(f"AssetSnapshot inválido: {errors}")
        self.errors = errors


@dataclasses.dataclass(frozen=True)
class AssetFragment:
    """Lo que un conector concreto aporta sobre un activo. asset_id es
    obligatorio (es la clave de reconciliación); el resto son campos que esa
    fuente conoce."""

    source: str
    asset_id: str
    fields: dict


@dataclasses.dataclass(frozen=True)
class ReconcileResult:
    payload: dict
    conflicts: list[dict]  # [{field, values: {source: value}}]


def reconcile(fragments: list[AssetFragment]) -> tuple[dict, list[dict]]:
    """Fusiona fragmentos del mismo asset_id. Devuelve (merged_fields,
    conflicts). No valida contra schema ni añade envelope — eso lo hace
    build_asset_snapshot_payload, que sí conoce el contrato."""
    if not fragments:
        raise ValueError("reconcile necesita al menos un fragmento")
    asset_ids = {f.asset_id for f in fragments}
    if len(asset_ids) > 1:
        raise ValueError(f"reconcile recibió fragmentos de activos distintos: {asset_ids}")

    merged: dict = {}
    seen_by_field: dict[str, dict[str, object]] = {}
    for fragment in fragments:
        for field in _MERGEABLE_FIELDS:
            if field not in fragment.fields:
                continue
            value = fragment.fields[field]
            seen_by_field.setdefault(field, {})[fragment.source] = value
            merged[field] = value  # última fuente gana en el valor final; el conflicto queda registrado igualmente

    conflicts = [
        {"field": field, "values": values}
        for field, values in seen_by_field.items()
        if len(set(values.values())) > 1
    ]
    return merged, conflicts


def build_asset_snapshot_payload(
    contracts_path,
    context: EnvelopeContext,
    asset_id: str,
    fragments: list[AssetFragment],
) -> ReconcileResult:
    merged_fields, conflicts = reconcile(fragments)
    snapshot_id = new_id_prefixed("asn")

    payload = {"asset_id": asset_id, **merged_fields}
    payload.setdefault("namespace", "unknown")
    payload.setdefault("criticality_esp", "medium")  # sin dato, no asumir "low" (mismo criterio que risk_engine)

    envelope = build_envelope(context, payload, message_id=snapshot_id)
    full_payload = {**envelope, **payload}

    registry = build_registry(contracts_path)
    errors = validate_payload(contracts_path, registry, "asset-snapshot", full_payload)
    if errors:
        raise InvalidAssetSnapshot(errors)

    return ReconcileResult(payload=full_payload, conflicts=conflicts)


def detect_drift(as_designed: dict, as_built: dict) -> list[dict]:
    """Compara dos AssetSnapshot del mismo activo (uno esperado, uno
    observado) campo a campo. Real, no un placeholder: cualquier
    _MERGEABLE_FIELDS distinto entre ambos es drift reportable."""
    drift = []
    for field in _MERGEABLE_FIELDS:
        designed_value = as_designed.get(field)
        built_value = as_built.get(field)
        if designed_value != built_value:
            drift.append({"field": field, "as_designed": designed_value, "as_built": built_value})
    return drift
