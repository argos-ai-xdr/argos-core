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

## VERIFIED nunca alcanzable hoy — igual que SAFE_TO_EVALUATE

`mission_constraints_respected` es una constante `None`: Mission
Context no existe (`architecture/v0.6.25-gap-matrix.md` §12). Por eso
`verify()` nunca devuelve `VERIFIED` con el estado real del sistema,
incluso suministrando todos los demás hechos — mismo patrón y misma
honestidad que `safety_kernel` (ver su README). `decide_state()` se
prueba de forma aislada para demostrar que `VERIFIED` sí es alcanzable
por la lógica.

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
