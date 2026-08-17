# safety-kernel

ADR-054, ADR-051 (Fase H). Deterministic Safety Kernel entre
`recommendation` y `policy-adapter` (prompt maestro de arquitectura
objetivo, "SOVEREIGN SAFETY KERNEL"). Nunca decide autorización — eso
sigue siendo de OPA/HITL — y **SAFE_TO_EVALUATE ≠ APPROVED**: solo
habilita que la cadena siga evaluando.

## Las 14 comprobaciones, honestamente

De las 14 comprobaciones que pide el prompt, 5 son reales y siempre
evaluables hoy (`incident_valid`, `evidence_sufficient`,
`target_in_scope`, `action_reversible`/`rollback_available`,
`no_prohibited_action`), 7 son reales pero opcionales según lo que el
llamante pueda aportar (`target_exists`, `tool_active`,
`tool_digest_valid`, `blast_radius_bounded`,
`no_unresolved_critical_drift`, y desde ADR-062/Fase K también
`mission_impact_bounded` — vía `mission_context.assess_blast_radius`,
`None`/`INSUFFICIENT_CONTEXT` si no se evaluó, nunca "acotado" por
defecto), y **2 siguen siendo estructuralmente `None`** porque el
subsistema que las produciría no existe: `runbook_signed` (sin
Sovereign Root of Trust), `runtime_trust_valid` (sin
RuntimeTrustContext).

**Consecuencia real, no un defecto**: `evaluate()` nunca alcanza
`SAFE_TO_EVALUATE` con el estado actual del sistema — siempre queda en
`INCONCLUSIVE` como mínimo (o `BLOCKED` si además hay una violación
real). `decide_state()` (la lógica de transición, aislada de qué
produjo cada check) SÍ demuestra que `SAFE_TO_EVALUATE` es alcanzable
cuando corresponda — ver `tests/unit/test_safety_kernel.py`.

`ESCALATE` está en el tipo `SafetyKernelState` porque el prompt lo
define, pero ningún camino de este módulo lo produce todavía: exigiría
una señal de anomalía catastrófica (p. ej. "Critical red-team escape")
que ningún subsistema real emite hoy. Especificado, no alcanzable —
mismo principio que `ESCALATE`/`FREEZE`/`FALLBACK` en el resto del
prompt para estados que dependen de subsistemas inexistentes.

## SafetyEnvelope v1 — producido, no consumido todavía

`evaluate()` construye y valida un `SafetyEnvelope` real (contrato 11,
`argos-contracts-scenarios/schemas/safety-envelope/`) cuando las 14
comprobaciones dan `True`. **Nada en `policy_adapter`/`mcp_gateway`
lo consume todavía** — esa integración es el siguiente incremento real,
cuando exista un Independent Verifier que lo vete primero, tal como
especifica el propio flujo del prompt (`Recommendation → Safety Kernel →
SafetyEnvelope → Independent Verifier → OPA → HITL`). Conectar OPA
directamente a un SafetyEnvelope sin verificación independiente
invertiría ese orden.

## Qué NO hace

* No re-ejecuta ni simula nada (eso sería Security Digital Twin, que no existe).
* No firma el envelope con una clave real — `signature` es un checksum
  sha256 de integridad, mismo patrón ya documentado en
  `argos-cyber-tools/policies/approval.compute_signature_ref`.
* No consulta ningún repositorio hermano por su cuenta (inventario de
  activos, catálogo de tools, resultado de blast radius): todo hecho
  real llega como parámetro explícito en `SafetyCheckInput` — mantiene
  a `argos-core` sin acoplarse a la disposición en disco de
  `argos-cyber-tools`.
