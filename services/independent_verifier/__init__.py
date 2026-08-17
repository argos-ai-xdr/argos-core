"""independent_verifier: Independent Verification Barrier (ADR-055,
ADR-051 Fase H; prompt maestro de arquitectura objetivo, "INDEPENDENT
VERIFICATION BARRIER").

Situado entre SafetyEnvelope y OPA/PolicyDecision. No generativo. A
diferencia de `safety_kernel` (que evalúa la Recommendation cruda),
este módulo verifica que lo que el SafetyEnvelope YA PRODUJO sigue
siendo cierto, con hechos vueltos a consultar (`preconditions_hold`,
`blast_radius_bounded` se re-derivan frescos, no se reutiliza
directamente el resultado que vio el Safety Kernel) y con dos señales
que Safety Kernel nunca comprobó (`runbook_exists`, `rollback_executable`
vía dry-run real, no solo el flag `rollback_supported` del catálogo).

**INCONCLUSIVE y REJECTED significan lo mismo para ejecución: ZERO
EXECUTE.** Se mantienen como estados distintos solo para auditoría —
REJECTED es una violación conocida, INCONCLUSIVE es un hecho que no se
pudo confirmar de nuevo.

**K.1** (microcierre tras Fase K): `mission_constraints_respected` deja
de ser una constante `None` — re-verifica en fresco las restricciones de
misión que `safety_kernel` ya selló en `envelope["mission_bounds"]`
(ADR-062). No recalcula `MissionContext` desde cero (eso seguiría siendo
responsabilidad de `mission_context`) — comprueba que la REFERENCIA
sellada (`mission_context_hash`) coincide con una fresca, y que una
re-evaluación de `mission_blast_radius`/conflictos sigue siendo
aceptable. Mismo criterio de "hechos frescos, nunca reutilizados" que el
resto de este módulo.
"""
from __future__ import annotations

import dataclasses
from typing import Literal

VerificationState = Literal["VERIFIED", "INCONCLUSIVE", "REJECTED"]

#: Mismo umbral que safety_kernel.MAX_BLAST_RADIUS -- la verificación
#: independiente comprueba contra el límite que el propio envelope ya
#: declaró (envelope["max_blast_radius"]), no un valor propio distinto.


class InvalidVerificationInput(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class VerificationCheckInput:
    """Hechos frescos para re-verificar un SafetyEnvelope ya producido.
    Cada `X | None` es `None` cuando el llamante no puede confirmarlo de
    nuevo en el momento de verificar (p. ej. no volvió a consultar el
    inventario) — nunca se reutiliza silenciosamente el valor que vio
    `safety_kernel` como si fuera una confirmación fresca."""

    envelope: dict
    incident: dict
    tool_name: str
    target: str
    target_allowlist: frozenset[str]
    target_confirmed_live: bool | None = None
    runbook_exists: bool | None = None
    rollback_dry_run_ok: bool | None = None
    observed_blast_radius_count: int | None = None
    fresh_mission_context_hash: str | None = None  # re-consultado ahora, no el que vio safety_kernel (K.1)
    fresh_mission_blast_radius: str | None = None  # re-evaluación fresca de mission_context.assess_blast_radius (K.1)
    unresolved_semantic_conflicts: bool | None = None  # ¿hay algún SemanticConflict en REQUIRES_AUTHORITY que afecte a este target? (K.1)


@dataclasses.dataclass(frozen=True)
class VerificationCheck:
    name: str
    passed: bool | None  # None = NOT_EVALUATED
    detail: str


@dataclasses.dataclass(frozen=True)
class VerificationDecision:
    state: VerificationState
    checks: tuple[VerificationCheck, ...]
    reason: str

    @property
    def zero_execute(self) -> bool:
        """INCONCLUSIVE o REJECTED -> ZERO EXECUTE (literal del prompt)."""
        return self.state != "VERIFIED"

    @property
    def not_evaluated(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.checks if c.passed is None)

    @property
    def violated(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.checks if c.passed is False)


def _check_mission_constraints(envelope: dict, inp: VerificationCheckInput) -> tuple[bool | None, str]:
    """K.1: re-verifica en fresco las restricciones de misión que
    safety_kernel selló en envelope['mission_bounds'] -- nunca las
    recalcula desde cero (eso es responsabilidad de mission_context), y
    nunca confía en que sigan siendo ciertas sin volver a comprobarlas.
    UNKNOWN nunca se convierte en VERIFIED: cualquier hecho fresco no
    suministrado dej a el check en None (INCONCLUSIVE), nunca en True."""
    mission_bounds = envelope.get("mission_bounds")
    if mission_bounds is None:
        return None, "Safety Kernel no evaluó MissionContext para esta acción (mission_bounds ausente en el envelope)"

    sealed_hash = mission_bounds.get("mission_context_hash")
    if inp.fresh_mission_context_hash is not None and sealed_hash is not None and inp.fresh_mission_context_hash != sealed_hash:
        return False, f"MissionContext hash no coincide: sellado={sealed_hash!r}, fresco={inp.fresh_mission_context_hash!r} (referencia obsoleta o incorrecta)"

    if inp.fresh_mission_blast_radius is None:
        return None, "fresh_mission_blast_radius no re-suministrado en la verificación"
    if inp.fresh_mission_blast_radius == "INSUFFICIENT_CONTEXT":
        return None, "MissionContext sigue sin evaluación suficiente en la re-verificación fresca"
    if inp.fresh_mission_blast_radius == "CRITICAL":
        return False, "mission_blast_radius=CRITICAL en la re-verificación fresca"

    if inp.unresolved_semantic_conflicts is None:
        return None, "unresolved_semantic_conflicts no re-suministrado en la verificación"
    if inp.unresolved_semantic_conflicts:
        return False, "conflicto semántico sin resolver (REQUIRES_AUTHORITY) afecta a este target"

    return (
        True,
        f"mission_context_hash coincide con el sellado, mission_blast_radius={inp.fresh_mission_blast_radius!r} (no CRITICAL), sin conflictos sin resolver",
    )


def _run_checks(inp: VerificationCheckInput) -> tuple[VerificationCheck, ...]:
    envelope = inp.envelope

    references_resolve = (
        envelope.get("incident_ref") == inp.incident.get("incident_id")
        and envelope.get("rollback_ref") == f"rollback/{inp.tool_name}"
        and envelope.get("required_runbook") == f"runbooks/{inp.tool_name}.md"
    )

    evidence_refs = inp.incident.get("evidence_refs") or []
    facts_exist = bool(evidence_refs) or envelope.get("evidence_root") is not None

    targets_exist = inp.target_confirmed_live
    targets_exist_detail = (
        "target_confirmed_live no suministrado (inventario no re-consultado en verificación)"
        if targets_exist is None
        else f"target {inp.target!r} {'confirmado vivo' if targets_exist else 'ya NO presente'} en la re-consulta"
    )

    runbook_exists = inp.runbook_exists
    runbook_detail = (
        "runbook_exists no suministrado (safety_kernel nunca lo comprobó — runbook_signed siempre fue None)"
        if runbook_exists is None
        else f"{envelope.get('required_runbook')} {'existe' if runbook_exists else 'NO existe'} en argos-cyber-tools/runbooks/"
    )

    preconditions_hold = inp.target in inp.target_allowlist and inp.target in envelope.get("target_set", [])

    postconditions_measurable = bool(envelope.get("verification_predicates"))

    rollback_executable = inp.rollback_dry_run_ok
    rollback_detail = (
        "rollback_dry_run_ok no suministrado (más fuerte que rollback_supported del catálogo: exige un dry-run real)"
        if rollback_executable is None
        else f"dry-run de rollback {'confirmado ejecutable' if rollback_executable else 'FALLÓ'}"
    )

    max_blast_radius = envelope.get("max_blast_radius")
    if inp.observed_blast_radius_count is None:
        blast_radius_bounded = None
        blast_radius_detail = "observed_blast_radius_count no re-suministrado en verificación (no se reutiliza el valor visto por safety_kernel)"
    else:
        blast_radius_bounded = max_blast_radius is not None and inp.observed_blast_radius_count <= max_blast_radius
        blast_radius_detail = f"{inp.observed_blast_radius_count} recurso(s), máximo declarado en el envelope: {max_blast_radius}"

    mission_constraints_respected, mission_detail = _check_mission_constraints(envelope, inp)

    return (
        VerificationCheck("references_resolve", references_resolve, "incident_ref/rollback_ref/required_runbook consistentes con el envelope" if references_resolve else "el envelope no referencia a este incident/tool"),
        VerificationCheck("facts_exist", facts_exist, f"{len(evidence_refs)} evidence_ref(s) en el incident, evidence_root={envelope.get('evidence_root')!r}"),
        VerificationCheck("targets_exist", targets_exist, targets_exist_detail),
        VerificationCheck("runbook_exists", runbook_exists, runbook_detail),
        VerificationCheck("preconditions_hold", preconditions_hold, f"target {inp.target!r} {'en' if preconditions_hold else 'fuera de'} allowlist y target_set"),
        VerificationCheck("postconditions_measurable", postconditions_measurable, f"{len(envelope.get('verification_predicates', []))} verification_predicate(s)"),
        VerificationCheck("rollback_executable", rollback_executable, rollback_detail),
        VerificationCheck("blast_radius_bounded", blast_radius_bounded, blast_radius_detail),
        VerificationCheck("mission_constraints_respected", mission_constraints_respected, mission_detail),
    )


def decide_state(checks: tuple[VerificationCheck, ...]) -> tuple[VerificationState, str]:
    """Misma disciplina que safety_kernel.decide_state: una violación
    conocida pesa más que cualquier cantidad de checks sin evaluar.
    A diferencia de Safety Kernel, aquí INCONCLUSIVE y REJECTED
    convergen en el mismo efecto práctico (ZERO EXECUTE) — se
    distinguen solo para que la auditoría sepa si hubo una violación
    real o solo una confirmación pendiente."""
    violated = [c for c in checks if c.passed is False]
    if violated:
        names = ", ".join(c.name for c in violated)
        return "REJECTED", f"REJECTED: {names} (ZERO EXECUTE, ADR-055)"

    unevaluated = [c for c in checks if c.passed is None]
    if unevaluated:
        names = ", ".join(c.name for c in unevaluated)
        return "INCONCLUSIVE", f"INCONCLUSIVE: {names} no se pudo re-confirmar (ZERO EXECUTE, ADR-055)"

    return "VERIFIED", "VERIFIED — todas las comprobaciones independientes se reconfirmaron con hechos frescos"


def verify(inp: VerificationCheckInput) -> VerificationDecision:
    if not inp.envelope:
        raise InvalidVerificationInput("envelope vacío o ausente")
    checks = _run_checks(inp)
    state, reason = decide_state(checks)
    return VerificationDecision(state=state, checks=checks, reason=reason)
