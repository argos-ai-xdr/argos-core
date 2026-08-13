# tests

84 casos. Requieren `argos-contracts-scenarios` como hermano o `ARGOS_CONTRACTS_PATH` (ver `../docs/development.md`) — se saltan automáticamente (`pytest.skip`) si no lo encuentran.

| Carpeta | Contenido |
| --- | --- |
| `unit/` | Lógica pura de cada servicio y de `libs/argos_envelope` (incluida una regresión explícita del bug real de longitud de ID) |
| `contract/` | Barrido: cada servicio productor valida contra `argos-contracts-scenarios/schemas/` |
| `integration/` | normalizer → correlator → recommendation → policy_adapter → evidence_writer → soc_adapter encadenados de verdad |
| `replay/` | Reproduce un fixture real de `argos-contracts-scenarios/fixtures/smoke/` a través de varios servicios |
| `security/` | Chequeos estáticos: solo `evidence_writer` referencia `ceph://`; `recommendation` no importa nada que huela a ejecución |

Ejecutar: `make test` o `pytest`.
