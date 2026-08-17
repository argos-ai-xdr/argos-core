"""federation.sanitizer: sanitización determinista de payloads para
cross-domain transfer (Fase L; prompt maestro de arquitectura objetivo,
§13, "Deterministic sanitization").

Mismo payload + misma política de reglas -> mismas transformaciones,
mismo `released_hash`, siempre. Ninguna regla puede reintroducir un campo
ya eliminado: `apply_sanitization` opera sobre una copia profunda y solo
aplica las reglas explícitamente declaradas -- lo que no está en la
política no se toca, y lo que la política elimina no puede reaparecer
por una copia oculta que no fue declarada como objetivo (de ahí el
soporte de rutas de un nivel de anidación, p. ej. `metadata.note`, para
poder sanear duplicados conocidos, no para inventar saneamiento mágico).
"""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from typing import Literal

TransformationOp = Literal["REMOVE_FIELD", "REDACT_FIELD", "TOKENIZE_FIELD", "GENERALIZE_VALUE", "DROP_ATTACHMENT"]

REDACTED_PLACEHOLDER = "***REDACTED***"


@dataclasses.dataclass(frozen=True)
class SanitizationRule:
    field_path: str  # "field" o "parent.field" (un nivel de anidación)
    operation: TransformationOp
    detail: str = ""


@dataclasses.dataclass(frozen=True)
class Transformation:
    field_path: str
    operation: TransformationOp
    detail: str


@dataclasses.dataclass(frozen=True)
class SanitizationResult:
    original_hash: str
    released_hash: str
    released_payload: dict
    transformations: tuple[Transformation, ...]
    fields_removed: tuple[str, ...]


def _hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _tokenize(field_path: str, value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(f"{field_path}:{canonical}".encode()).hexdigest()[:16]
    return f"tok_{digest}"


def _split(field_path: str) -> tuple[str, str | None]:
    if "." in field_path:
        parent, child = field_path.split(".", 1)
        return parent, child
    return field_path, None


def _apply_one(working: dict, rule: SanitizationRule) -> Transformation | None:
    top, nested = _split(rule.field_path)
    if top not in working:
        return None
    container = working
    key = top
    if nested is not None:
        if not isinstance(working[top], dict) or nested not in working[top]:
            return None
        container = working[top]
        key = nested

    if rule.operation == "REMOVE_FIELD" or rule.operation == "DROP_ATTACHMENT":
        del container[key]
    elif rule.operation == "REDACT_FIELD":
        container[key] = REDACTED_PLACEHOLDER
    elif rule.operation == "TOKENIZE_FIELD":
        container[key] = _tokenize(rule.field_path, container[key])
    elif rule.operation == "GENERALIZE_VALUE":
        container[key] = rule.detail or "GENERALIZED"

    return Transformation(field_path=rule.field_path, operation=rule.operation, detail=rule.detail)


def apply_sanitization(payload: dict, rules: tuple[SanitizationRule, ...]) -> SanitizationResult:
    original_hash = _hash(payload)
    working = copy.deepcopy(payload)
    transformations: list[Transformation] = []
    fields_removed: list[str] = []

    for rule in sorted(rules, key=lambda r: r.field_path):
        applied = _apply_one(working, rule)
        if applied is None:
            continue
        transformations.append(applied)
        if rule.operation in ("REMOVE_FIELD", "DROP_ATTACHMENT"):
            fields_removed.append(rule.field_path)

    released_hash = _hash(working)
    return SanitizationResult(
        original_hash=original_hash,
        released_hash=released_hash,
        released_payload=working,
        transformations=tuple(transformations),
        fields_removed=tuple(fields_removed),
    )
