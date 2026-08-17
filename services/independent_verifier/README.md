# independent-verifier

ADR-055, ADR-051 (Fase H). Independent Verification Barrier entre
`safety_kernel` y `policy-adapter` (prompt maestro de arquitectura
objetivo, "INDEPENDENT VERIFICATION BARRIER"). No generativo.

## Por qué es "independiente" de verdad, no solo un nombre

No reutiliza los mismos hechos que vio `safety_kernel` como si
siguieran siendo ciertos:

* `preconditions_hold` vuelve a comprobar el target contra una
  `target_allowlist` recién suministrada — si la allowlist cambió entre
  que se construyó el `SafetyEnvelope` y ahora, esto lo detecta.
* `blast_radius_bounded` exige un `observed_blast_radius_count` fresco,
  no el que vio `safety_kernel`.
* `runbook_exists` y `rollback_executable` (vía `rollback_dry_run_ok`)
  son señales que `safety_kernel` **nunca tuvo** — ese módulo solo
  comprobaba `runbook_signed` (siempre `None`, no existe firma) y
  `rollback_supported` (un flag del catálogo, no una prueba real). Aquí
  se pide una confirmación más fuerte: que el runbook exista de verdad
  y que un dry-run de rollback haya sido intentado y confirmado.
* `references_resolve` comprueba estructuralmente que el envelope no
  fue alterado o mal-emparejado (`incident_ref`/`rollback_ref`/
  `required_runbook` deben ser exactamente los que este `tool_name`/
  `incident` producirían).

## `mission_constraints_respected` real (K.1)

Desde el microcierre K.1, `mission_constraints_respected` ya NO es una
constante `None` — re-verifica en fresco lo que `safety_kernel` selló en
`envelope["mission_bounds"]` (ADR-062): que un `mission_context_hash`
recién consultado coincida con el sellado (detecta referencia obsoleta
o incorrecta), que una re-evaluación de `mission_blast_radius` siga sin
ser `CRITICAL`, y que no haya conflictos semánticos sin resolver
afectando al target. **No recalcula `MissionContext` desde cero** —
verifica la REFERENCIA, no reconstruye el cálculo (eso sigue siendo
responsabilidad exclusiva de `mission_context`).

`VERIFIED` es ahora alcanzable por un checkout real (probado en
`tests/integration/test_k1_mission_verifier_vertical_slice.py`) cuando
TODOS los hechos frescos —incluidos los de misión— se confirman. Sigue
sin ser una aprobación: la única vía de autorización real sigue siendo
`policy_adapter`/`Approval` (ADR-011).

## INCONCLUSIVE y REJECTED → ZERO EXECUTE

El prompt es explícito: ambos estados no-`VERIFIED` tienen el mismo
efecto práctico (`VerificationDecision.zero_execute`). Se mantienen
distintos solo para que la auditoría sepa si hubo una violación
conocida (`REJECTED`) o un hecho que no se pudo reconfirmar
(`INCONCLUSIVE`) — la misma distinción que `BLOCKED`/`INCONCLUSIVE` en
`safety_kernel`.

## Qué NO hace

* No produce ningún contrato nuevo — `VerificationDecision` es un
  artefacto interno de `argos-core`, igual que `ReplayCapsule` en
  `argos-validation`: nada lo consume todavía fuera de este repo, así
  que formalizarlo como contrato v1 cross-repo sería prematuro (mismo
  criterio que ADR-051 aplica a "no scaffolding vacío").
* No re-ejecuta el tool ni simula su efecto (eso sería Security Digital
  Twin, que no existe).
