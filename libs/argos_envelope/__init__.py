"""Construye el envelope común (ADR-001) que envuelve los 10 contratos v1 de
argos-contracts-scenarios. Reutilizado por todos los servicios de
argos-core para no reimplementar el hash/los campos comunes siete veces.
"""
from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import uuid


def new_id_prefixed(prefix: str) -> str:
    """ID legible con prefijo de dominio (evt-, inc-, reco-, ...) que
    cumple SIEMPRE el pattern del envelope (^[0-9A-Za-z-]{20,36}$, ver
    argos-contracts-scenarios/envelope/v1/): trunca el hex para que el total
    sea exactamente 36 caracteres, en vez de asumir que "prefix corto +
    hex de 32" siempre cabe (con prefix de 4 caracteres eso da 37, no 36 —
    error real encontrado probando esta función contra el schema real)."""
    if not (1 <= len(prefix) <= 15):
        raise ValueError("prefix debe tener entre 1 y 15 caracteres")
    hex_len = 36 - len(prefix) - 1  # -1 por el guion separador
    return f"{prefix}-{uuid.uuid4().hex[:hex_len]}"


def sha256_of_payload(payload: dict) -> str:
    """Hash determinista del payload (claves ordenadas) — usado como
    payload_hash del envelope. No es el hash de un archivo (eso lo hace
    argos_evidence), es el hash del contenido lógico del mensaje."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


@dataclasses.dataclass(frozen=True)
class EnvelopeContext:
    """Campos de envelope que un servicio conoce de antemano (identidad
    propia + correlación de la ejecución) — no incluye id/payload_hash, que
    se calculan por mensaje en build_envelope."""

    producer: str
    run_id: str
    classification: str = "internal"
    trace_id: str | None = None
    schema_version: str = "1.0.0"


def build_envelope(context: EnvelopeContext, payload: dict, *, message_id: str, native_ref: str | None = None) -> dict:
    """Devuelve los campos de envelope listos para fusionar con los campos
    específicos del contrato (dict.update). No incluye evidence_refs — cada
    productor los añade si tiene evidencia que referenciar."""
    envelope = {
        "id": message_id,
        "schema_version": context.schema_version,
        "observed_at": utc_now_iso(),
        "producer": context.producer,
        "classification": context.classification,
        "run_id": context.run_id,
        "payload_hash": sha256_of_payload(payload),
    }
    if context.trace_id:
        envelope["trace_id"] = context.trace_id
    if native_ref:
        envelope["native_ref"] = native_ref
    return envelope
