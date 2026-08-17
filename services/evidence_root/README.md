# evidence-root

ADR-057, ADR-051 (Fase J). Cierra el linaje `Run/Action/Verification →
EvidenceManifest → EvidenceRoot → Transparency record` sobre evidencia
ya real (`evidence_writer`), sin fabricar infraestructura criptográfica
o de transparencia externa que no existe.

| Módulo | Rol |
| --- | --- |
| [`__init__.py`](__init__.py) | `EvidenceRoot`: agregador determinista de `EvidenceManifest` reales — hash agregado (no Merkle, ver ADR-057), orden de entrada irrelevante, detecta duplicados conflictivos y artefactos ausentes |
| [`transparency_log.py`](transparency_log.py) | `TransparencyLog`: append-only local con hash-chain real (`previous_entry_hash`), `TransparencyReceipt` sin firma |
| [`replay.py`](replay.py) | Reconstrucción/verificación: `VERIFIED / INCOMPLETE / HASH_MISMATCH / BROKEN_CHAIN / MISSING_ARTIFACT` |

## Qué es real hoy

* Todo lo anterior corre en memoria de un único proceso (mismo caveat
  documentado en `ApprovalStore`/`IdempotencyStore` desde el principio
  del proyecto), con persistencia OPCIONAL a un archivo JSONL vía
  `TransparencyLog(persist_path=...)` — un `open(path, "a")` real, no
  simulado.
* `EvidenceRoot`/`TransparencyLog` son **`LOGICALLY_APPEND_ONLY /
  TAMPER_EVIDENT`**, nunca `IMMUTABLE`: nada impide que alguien con
  acceso directo al proceso o al archivo edite una entrada — lo que
  garantizan es que esa edición sea *detectable*
  (`verify_chain()`/`verify_evidence_root()` recomputan hashes desde
  cero, nunca confían en el campo que ya trae el dato).
* `tests/integration/test_evidence_vertical_slice.py` demuestra el
  ciclo completo con las 3 acciones `execute` REALES de Fase I
  (`isolate_kubernetes_workload`, `scale_to_zero`,
  `increase_monitoring`) — los fixtures son la salida literal de
  invocar ese código, no datos inventados.

## Qué NO es real todavía (BLOCKED_EXTERNAL / SPECIFIED)

* **Firma criptográfica real** de `EvidenceRoot`/`TransparencyReceipt`:
  no existe ninguna PKI en este proyecto (ARG-002/ARG-020). Ningún campo
  de firma se declara donde no puede cumplirse — `TransparencyReceipt`
  no tiene campo `signature` en absoluto (a propósito, no un `null`).
* **Merkle tree**: decisión explícita de NO construirlo — ningún
  contrato lo exige, y el precedente ya establecido en este mismo
  proyecto (`argos-validation/harness/acceptance.py::seal_report`) usa
  hash agregado simple. Ver ADR-057.
* **Object-lock/WORM real** en el storage: Ceph RGW no está desplegado
  (ARG-026); la garantía "tamper-evident" de este módulo es lógica, no
  de almacenamiento.
* **Sovereign Root of Trust / Transparency service externo tipo
  Sigstore**: no existen, no se simulan aquí.
* **EvidenceRoot como contrato v1 cross-repo**: se mantiene interno a
  `argos-core` (mismo criterio que `ReplayCapsule` en
  `argos-validation` y `VerificationResult` en `independent_verifier`)
  — nada fuera de este repositorio lo consume todavía.

## Distinto de `argos-smartops/api/audit.py::AuditLog`

`AuditLog` ya existía (sin borrado/modificación expuestos) pero **no
encadena hashes** (no es tamper-evident, solo "sin API de borrado") y
solo cubre acciones de operador dentro de ese servicio — no
promoción/revocación de componentes de IA/política/modelo a nivel de
plataforma, que es lo que `CLAIM-010` de
`argos-control/assurance/argos-assurance.yaml` pedía.
