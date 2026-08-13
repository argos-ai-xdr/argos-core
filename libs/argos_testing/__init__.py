"""Helpers de test compartidos: resuelve el checkout de
argos-contracts-scenarios y valida payloads contra sus schemas. Mismo patrón
que argos-validation/harness/loaders/ (registry con $ref cruzado resuelto vía
referencing.Registry) — vive aquí también porque los tests de contrato de
argos-core (tests/contract/) lo necesitan directamente, no solo el harness.
"""
from __future__ import annotations

import json
import os
import pathlib

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

CONTRACTS_ENV_VAR = "ARGOS_CONTRACTS_PATH"


class ContractsRepoNotFound(RuntimeError):
    pass


def resolve_contracts_path(start: pathlib.Path | None = None) -> pathlib.Path:
    env_value = os.environ.get(CONTRACTS_ENV_VAR)
    if env_value:
        path = pathlib.Path(env_value).expanduser().resolve()
        if not path.exists():
            raise ContractsRepoNotFound(f"{CONTRACTS_ENV_VAR}={env_value!r} no existe")
        return path

    base = start or pathlib.Path(__file__).resolve().parents[2]
    sibling = (base.parent / "argos-contracts-scenarios").resolve()
    if sibling.exists():
        return sibling

    raise ContractsRepoNotFound(
        "No se encontró argos-contracts-scenarios. Clónalo como hermano de "
        f"este repositorio o define {CONTRACTS_ENV_VAR}."
    )


def build_registry(contracts_path: pathlib.Path) -> Registry:
    schemas_dir = contracts_path / "schemas"
    envelope_path = contracts_path / "envelope" / "v1" / "argos-envelope.schema.json"
    resources = []
    for path in list(schemas_dir.rglob("*.schema.json")) + [envelope_path]:
        data = json.loads(path.read_text(encoding="utf-8"))
        resources.append((path.as_uri(), Resource.from_contents(data)))
    return Registry().with_resources(resources)


def validator_for(contracts_path: pathlib.Path, registry: Registry, contract: str) -> Draft202012Validator:
    schema_path = contracts_path / "schemas" / contract / "v1.schema.json"
    if not schema_path.exists():
        raise FileNotFoundError(f"No existe schemas/{contract}/v1.schema.json en {contracts_path}")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema = {**schema, "$id": schema_path.as_uri()}
    return Draft202012Validator(schema, registry=registry)


def validate_payload(contracts_path: pathlib.Path, registry: Registry, contract: str, payload: dict) -> list[str]:
    """Devuelve la lista de errores de schema (vacía si el payload es válido)."""
    validator = validator_for(contracts_path, registry, contract)
    return [e.message for e in validator.iter_errors(payload)]


def load_fixture(contracts_path: pathlib.Path, category: str, contract: str, filename: str) -> dict:
    path = contracts_path / "fixtures" / category / contract / filename
    return json.loads(path.read_text(encoding="utf-8"))
