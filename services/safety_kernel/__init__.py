"""safety_kernel: Deterministic Safety Kernel (ADR-054, ADR-051 Fase H;
prompt maestro de arquitectura objetivo, "SOVEREIGN SAFETY KERNEL").

Situado entre Recommendation y OPA/PolicyDecision. Determinista y NO
generativo: nunca invoca un modelo, nunca decide autorización (eso sigue
siendo de OPA) y nunca ejecuta nada — solo valida los límites de una
Recommendation ya emitida y produce un SafetyEnvelope si es seguro
seguir evaluándola.

**SAFE_TO_EVALUATE ≠ APPROVED.** Un SafetyEnvelope habilita que OPA y
luego un humano evalúen la acción — no la autoriza. La autorización real
sigue viviendo exclusivamente en `policy_adapter`/`Approval` (ADR-011).

Las 14 comprobaciones del prompt se implementan con la misma disciplina
que el resto de esta sesión: nunca se fabrica un resultado. Cada
comprobación recibe su hecho del LLAMANTE (`SafetyCheckInput`) — si el
llamante no puede aportarlo porque el subsistema que lo produciría no
existe todavía (RuntimeTrustContext, firma de runbooks), el campo es
`None` y la comprobación queda NOT_EVALUATED, nunca en PASS por defecto.
Desde ADR-062 (Fase K), `mission_impact_bounded` YA es un hecho real
suministrable (`mission_context.assess_blast_radius`) — MissionContext
nunca decide autorización, solo aporta un hecho más de entrada. Ver
`README.md` de este módulo para qué hecho viene de dónde en un sistema
real.
"""
from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
from typing import Literal

from argos_envelope import EnvelopeContext, build_envelope, new_id_prefixed
from argos_testing import build_registry, validate_payload

SafetyKernelState = Literal["SAFE_TO_EVALUATE", "BLOCKED", "INCONCLUSIVE", "ESCALATE"]

#: Alineado con argos-cyber-tools/graph/blast_radius.py: GO/NARROW hasta
#: 2 recursos afectados, STOP a partir de 3 (mismo umbral, no un valor
#: inventado aparte).
MAX_BLAST_RADIUS = 2

#: Ningún tool del catálogo actual opera sobre más de un target a la vez.
MAX_TARGETS = 1

#: Único entorno de ejecución real hoy (architecture/trust-zones/trust-zones.md).
EXECUTION_ENVIRONMENT = "argos-cyber-range"

#: Única regla de política real y probada hoy (InMemoryPolicyDecisionPoint).
POLICY_REF = "F07"

#: TTL del envelope: mismo valor que el TTL real de Approval (ApprovalStore),
#: no una constante nueva sin relación con lo que ya existe.
ENVELOPE_TTL_MINUTES = 15


class InvalidSafetyEnvelope(Exception):
    def __init__(self, errors: list[str]):
        super().__init__(f"SafetyEnvelope inválido: {errors}")
        self.errors = errors


@dataclasses.dataclass(frozen=True)
class SafetyCheckInput:
    """Todo lo que el Safety Kernel necesita para evaluar una
    Recommendation. Cada campo `X | None` es `None` cuando el hecho
    real todavía no es computable en este sistema (ver docstring de la
    comprobación correspondiente en `evaluate()`) — el llamante nunca
    debe rellenarlo con un valor optimista."""

    incident: dict
    recommendation: dict
    target: str
    tool_name: str
    tool_modes: tuple[str, ...]
    side_effect_class: str
    rollback_supported: bool
    tool_timeout_seconds: int
    tool_known: bool
    target_allowlist: frozenset[str]
    evidence_manifest_id: str | None = None
    known_asset_ids: frozenset[str] | None = None
    tool_digest_valid: bool | None = None
    observed_blast_radius_count: int | None = None
    no_unresolved_critical_drift: bool | None = None
    mission_blast_radius: str | None = None  # "NONE"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL"|"INSUFFICIENT_CONTEXT", ver mission_context.MissionImpactLevel (ADR-062, Fase K)


@dataclasses.dataclass(frozen=True)
class SafetyCheck:
    name: str
    passed: bool | None  # None = NOT_EVALUATED
    detail: str


@dataclasses.dataclass(frozen=True)
class SafetyKernelDecision:
    state: SafetyKernelState
    checks: tuple[SafetyCheck, ...]
    envelope: dict | None  # payload de SafetyEnvelope v1 ya validado, solo si state == SAFE_TO_EVALUATE
    reason: str

    @property
    def not_evaluated(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.checks if c.passed is None)

    @property
    def violated(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.checks if c.passed is False)


def _run_checks(inp: SafetyCheckInput, *, contracts_path, registry) -> tuple[SafetyCheck, ...]:
    incident_errors = validate_payload(contracts_path, registry, "incident", inp.incident)
    incident_valid = not incident_errors

    evidence_refs = inp.incident.get("evidence_refs") or inp.recommendation.get("rationale_refs") or []
    evidence_sufficient = bool(evidence_refs)

    target_exists: bool | None
    if inp.known_asset_ids is None:
        target_exists = None
        target_exists_detail = "known_asset_ids no suministrado por el llamante (inventario no consultado)"
    else:
        target_exists = inp.target in inp.known_asset_ids
        target_exists_detail = f"target {inp.target!r} {'en' if target_exists else 'ausente de'} el inventario suministrado"

    target_in_scope = inp.target in inp.target_allowlist

    tool_active = inp.tool_known

    tool_digest_valid = inp.tool_digest_valid
    tool_digest_detail = (
        "no suministrado por el llamante (integridad del catálogo no comprobada en esta llamada)"
        if tool_digest_valid is None
        else f"verify_integrity_manifest reportó {'sin discrepancias' if tool_digest_valid else 'discrepancia'}"
    )

    # No existe ningún mecanismo de firma de runbooks (Sovereign Root of
    # Trust no existe, ARG-002/ARG-020 pendientes) -- constante, no un
    # parámetro que alguien pudiera rellenar con un True optimista.
    runbook_signed = None

    action_reversible = inp.rollback_supported
    rollback_available = inp.rollback_supported  # misma señal real; no hay una segunda fuente independiente hoy

    blast_radius_bounded: bool | None
    if inp.observed_blast_radius_count is None:
        blast_radius_bounded = None
        blast_radius_detail = "observed_blast_radius_count no suministrado (graph.blast_radius no invocado desde aquí)"
    else:
        blast_radius_bounded = inp.observed_blast_radius_count <= MAX_BLAST_RADIUS
        blast_radius_detail = f"{inp.observed_blast_radius_count} recurso(s) afectados, máximo {MAX_BLAST_RADIUS}"

    # ADR-062 (Fase K): Mission Context ya existe (mission_context.assess_blast_radius)
    # -- mission_impact_bounded es un hecho real suministrable, no una
    # constante. "Bounded" = todo lo que no sea CRITICAL; INSUFFICIENT_CONTEXT
    # (sin MissionContext evaluado) sigue siendo None, nunca "acotado por defecto".
    if inp.mission_blast_radius is None or inp.mission_blast_radius == "INSUFFICIENT_CONTEXT":
        mission_impact_bounded = None
        mission_impact_detail = "mission_blast_radius no suministrado o INSUFFICIENT_CONTEXT (MissionContext no evaluado para este target)"
    else:
        mission_impact_bounded = inp.mission_blast_radius != "CRITICAL"
        mission_impact_detail = f"mission_blast_radius={inp.mission_blast_radius!r} ({'acotado' if mission_impact_bounded else 'CRITICAL, no acotado'})"

    # RuntimeTrustContext no existe (architecture/v0.6.25-gap-matrix.md §21-38).
    runtime_trust_valid = None

    no_unresolved_critical_drift = inp.no_unresolved_critical_drift
    drift_detail = (
        "no suministrado por el llamante (evaluators/drift no consultado para este target)"
        if no_unresolved_critical_drift is None
        else f"drift crítico {'ausente' if no_unresolved_critical_drift else 'presente y sin resolver'}"
    )

    no_prohibited_action = inp.side_effect_class not in ("IRREVERSIBLE", "DESTRUCTIVE")

    return (
        SafetyCheck("incident_valid", incident_valid, "; ".join(incident_errors) or "Incident v1 válido"),
        SafetyCheck("evidence_sufficient", evidence_sufficient, f"{len(evidence_refs)} evidence_ref(s)"),
        SafetyCheck("target_exists", target_exists, target_exists_detail),
        SafetyCheck("target_in_scope", target_in_scope, f"target {inp.target!r} {'en' if target_in_scope else 'fuera de'} la allowlist"),
        SafetyCheck("tool_active", tool_active, f"tool {inp.tool_name!r} {'presente' if tool_active else 'ausente'} en el catálogo"),
        SafetyCheck("tool_digest_valid", tool_digest_valid, tool_digest_detail),
        SafetyCheck("runbook_signed", runbook_signed, "sin mecanismo de firma de runbooks todavía (Sovereign Root of Trust no existe)"),
        SafetyCheck("action_reversible", action_reversible, f"rollback_supported={inp.rollback_supported}"),
        SafetyCheck("rollback_available", rollback_available, f"rollback_supported={inp.rollback_supported}"),
        SafetyCheck("blast_radius_bounded", blast_radius_bounded, blast_radius_detail),
        SafetyCheck("mission_impact_bounded", mission_impact_bounded, mission_impact_detail),
        SafetyCheck("runtime_trust_valid", runtime_trust_valid, "RuntimeTrustContext no existe todavía"),
        SafetyCheck("no_unresolved_critical_drift", no_unresolved_critical_drift, drift_detail),
        SafetyCheck(
            "no_prohibited_action",
            no_prohibited_action,
            f"side_effect_class={inp.side_effect_class!r} ({'permitido' if no_prohibited_action else 'DENY incondicional, ADR-053'})",
        ),
    )


def _canonical_hash(payload: dict, *, exclude: frozenset[str]) -> str:
    reduced = {k: v for k, v in payload.items() if k not in exclude}
    canonical = json.dumps(reduced, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_envelope_payload(inp: SafetyCheckInput, checks: tuple[SafetyCheck, ...]) -> dict:
    allowed_actions = [m for m in inp.tool_modes if m != "execute" or (inp.rollback_supported and inp.side_effect_class == "REVERSIBLE_WRITE")]
    forbidden_actions = [m for m in inp.tool_modes if m not in allowed_actions]
    if inp.side_effect_class in ("IRREVERSIBLE", "DESTRUCTIVE"):
        forbidden_actions = list(inp.tool_modes)
        allowed_actions = []

    not_evaluated = [c.name for c in checks if c.passed is None]
    residual_risk = (
        "Ningún check queda sin evaluar."
        if not not_evaluated
        else f"NOT_EVALUATED: {', '.join(not_evaluated)} — no se asume PASS para ninguno."
    )

    now = datetime.datetime.now(datetime.UTC)
    envelope_id = new_id_prefixed("safenv")

    verification_predicates = [
        f"rollback_supported=={inp.rollback_supported} para {inp.tool_name!r}",
    ]
    if inp.observed_blast_radius_count is not None:
        verification_predicates.append(f"blast_radius_count<= {MAX_BLAST_RADIUS} (observado: {inp.observed_blast_radius_count})")

    payload = {
        "envelope_id": envelope_id,
        "incident_ref": inp.incident.get("incident_id", ""),
        "evidence_root": inp.evidence_manifest_id,
        "target_set": [inp.target],
        "allowed_actions": allowed_actions,
        "forbidden_actions": forbidden_actions,
        "max_targets": MAX_TARGETS,
        "max_blast_radius": MAX_BLAST_RADIUS,
        "max_duration": inp.tool_timeout_seconds,
        "execution_environment": EXECUTION_ENVIRONMENT,
        "required_runbook": f"runbooks/{inp.tool_name}.md",
        "verification_predicates": verification_predicates,
        "rollback_ref": f"rollback/{inp.tool_name}",
        "runtime_trust_ref": None,
        "mission_bounds": None,
        "policy_ref": POLICY_REF,
        "residual_risk": residual_risk,
        "valid_until": (now + datetime.timedelta(minutes=ENVELOPE_TTL_MINUTES)).isoformat(),
    }
    envelope_hash = _canonical_hash(payload, exclude=frozenset({"envelope_hash", "signature"}))
    payload["envelope_hash"] = envelope_hash
    payload["signature"] = "sha256:" + hashlib.sha256(f"{envelope_hash}:{payload['incident_ref']}".encode()).hexdigest()
    return payload


def decide_state(checks: tuple[SafetyCheck, ...]) -> tuple[SafetyKernelState, str]:
    """Lógica de transición de estados, aislada de qué produjo cada
    `SafetyCheck` — probable de forma independiente para demostrar que
    SAFE_TO_EVALUATE es alcanzable POR LA LÓGICA incluso el día de hoy
    ningún checkout real de este repo pueda producir ese resultado
    (3 de las 14 comprobaciones son `None` de forma estructural mientras
    RuntimeTrustContext/Mission Context/Sovereign Root of Trust no
    existan — ver `_run_checks`). Fail-closed: cualquier violación
    conocida pesa más que cualquier cantidad de checks no evaluados."""
    violated = [c for c in checks if c.passed is False]
    if violated:
        names = ", ".join(c.name for c in violated)
        return "BLOCKED", f"BLOCKED: {names} (fail-closed, ADR-054)"

    unevaluated = [c for c in checks if c.passed is None]
    if unevaluated:
        names = ", ".join(c.name for c in unevaluated)
        return "INCONCLUSIVE", f"INCONCLUSIVE: sin violaciones conocidas, pero {names} no se pudo evaluar — no se asume seguro"

    return "SAFE_TO_EVALUATE", "SAFE_TO_EVALUATE — habilita evaluación por OPA/HITL; NO es una aprobación (SAFE_TO_EVALUATE ≠ APPROVED)"


def evaluate(
    inp: SafetyCheckInput,
    *,
    contracts_path,
    context: EnvelopeContext,
) -> SafetyKernelDecision:
    registry = build_registry(contracts_path)
    checks = _run_checks(inp, contracts_path=contracts_path, registry=registry)
    state, reason = decide_state(checks)

    if state != "SAFE_TO_EVALUATE":
        return SafetyKernelDecision(state=state, checks=checks, envelope=None, reason=reason)

    envelope_payload = _build_envelope_payload(inp, checks)
    full_payload = {**build_envelope(context, envelope_payload, message_id=envelope_payload["envelope_id"]), **envelope_payload}
    errors = validate_payload(contracts_path, registry, "safety-envelope", full_payload)
    if errors:
        raise InvalidSafetyEnvelope(errors)

    return SafetyKernelDecision(state="SAFE_TO_EVALUATE", checks=checks, envelope=full_payload, reason=reason)


def action_request_within_envelope(*, target: str, action: str, envelope: dict) -> bool:
    """Invariante del prompt: ActionRequest ⊆ SafetyEnvelope. Un
    ActionRequest hipotético (target, action) solo es válido si ambos
    caen dentro de lo que el envelope autorizó — comprobación real y
    barata, no una nota de intención sin código detrás."""
    return target in envelope["target_set"] and action in envelope["allowed_actions"]
