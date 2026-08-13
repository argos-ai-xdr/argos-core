# Desarrollo en argos-core

## Requisitos

* Python >= 3.11.
* `argos-contracts-scenarios` clonado como hermano de este repositorio (o `ARGOS_CONTRACTS_PATH`), igual que en `argos-validation`:

```text
argos-ai-xdr/
├── argos-core/                (este repositorio)
└── argos-contracts-scenarios/
```

## Comandos

```bash
make bootstrap   # pip install -e ".[dev]" + pre-commit install
make validate    # ruff + mypy + YAML/JSON
make test        # pytest (incluye tests de contrato contra argos-contracts-scenarios)
```

## Convención de paquetes

`libs/`, `services/` y `connectors/` son tres raíces de paquetes de nivel superior (ver `pyproject.toml`, `[tool.setuptools.packages.find]`). `import normalizer`, `import argos_envelope`, `import netbox` — nunca `import services.normalizer`.

## Cómo añadir un servicio o conector

1. Crear el paquete en `services/<nombre_paquete>/` o `connectors/<nombre_paquete>/` con `__init__.py`.
2. Si produce o consume un contrato, validar contra `argos-contracts-scenarios/schemas/<contrato>/v1.schema.json` — reutilizar `argos_envelope`/`argos_testing` en vez de reimplementar la carga de schemas.
3. Añadir pruebas en `tests/unit/` (lógica pura) y, si aplica, `tests/contract/` (validación de schema).
4. Documentar en el `README.md` del servicio/conector qué está implementado y qué es interfaz pendiente (ARG-### correspondiente).

## Antes de abrir un PR

1. `make validate` y `make test` sin errores.
2. El PR enlaza una historia `ARG-###`.
3. Ninguna salida nueva se salta la validación de schema.
