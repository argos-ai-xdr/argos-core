from __future__ import annotations

import pytest
from safety_kernel import (
    InvalidSafetyEnvelope,
    SafetyCheck,
    SafetyCheckInput,
    action_request_within_envelope,
    decide_state,
    evaluate,
)

pytestmark = pytest.mark.filterwarnings("ignore")


def _incident(**overrides: object) -> dict:
    base: dict[str, object] = {
        "id": "01J0SAFETY0000000000000001",
        "schema_version": "1.0.0",
        "observed_at": "2026-08-17T09:00:00Z",
        "producer": "correlator",
        "classification": "internal",
        "run_id": "run-safety-001",
        "payload_hash": "sha256:" + "0" * 64,
        "incident_id": "inc-safety-001",
        "member_event_ids": ["evt-1"],
        "timeline": [{"timestamp": "2026-08-17T09:00:00Z", "description": "x"}],
        "entities": [{"type": "asset", "id": "asset-x"}],
        "severity": "high",
        "evidence_refs": ["fixtures/smoke/security-event/wazuh-alert-001.json"],
    }
    base.update(overrides)
    return base


def _recommendation(**overrides: object) -> dict:
    base: dict[str, object] = {
        "recommendation_id": "reco-safety-001",
        "incident_id": "inc-safety-001",
        "alternatives": [{"action": "isolate_kubernetes_workload", "description": "aislar"}],
        "selected_action": "isolate_kubernetes_workload",
        "rationale_refs": ["fixtures/smoke/security-event/wazuh-alert-001.json"],
        "impact": "x",
        "uncertainty": "baja",
        "rollback_plan": "revertir la política",
    }
    base.update(overrides)
    return base


def _input(**overrides: object) -> SafetyCheckInput:
    base: dict[str, object] = {
        "incident": _incident(),
        "recommendation": _recommendation(),
        "target": "deployment/gseg-simulado",
        "tool_name": "isolate_kubernetes_workload",
        "tool_modes": ("dry-run", "execute"),
        "side_effect_class": "REVERSIBLE_WRITE",
        "rollback_supported": True,
        "tool_timeout_seconds": 30,
        "tool_known": True,
        "target_allowlist": frozenset({"deployment/gseg-simulado"}),
        "evidence_manifest_id": None,
        "known_asset_ids": frozenset({"deployment/gseg-simulado"}),
        "tool_digest_valid": True,
        "observed_blast_radius_count": 1,
        "no_unresolved_critical_drift": True,
    }
    base.update(overrides)
    return SafetyCheckInput(**base)


# ---------------------------------------------------------------------------
# decide_state: lógica de transición pura, independiente de qué produjo cada
# SafetyCheck.
# ---------------------------------------------------------------------------


def test_decide_state_all_true_is_safe_to_evaluate():
    checks = tuple(SafetyCheck(n, True, "ok") for n in ("a", "b", "c"))
    state, reason = decide_state(checks)
    assert state == "SAFE_TO_EVALUATE"
    assert "APPROVED" in reason  # recuerda explícitamente que no es una aprobación


def test_decide_state_any_false_is_blocked_even_with_other_unevaluated():
    checks = (SafetyCheck("a", True, "ok"), SafetyCheck("b", False, "violado"), SafetyCheck("c", None, "?"))
    state, reason = decide_state(checks)
    assert state == "BLOCKED"
    assert "b" in reason


def test_decide_state_none_without_violation_is_inconclusive():
    checks = (SafetyCheck("a", True, "ok"), SafetyCheck("b", None, "no evaluado"))
    state, reason = decide_state(checks)
    assert state == "INCONCLUSIVE"
    assert "b" in reason


def test_decide_state_violation_always_outweighs_unevaluated():
    """Fail-closed real: una violación conocida pesa más que cualquier
    cantidad de checks sin evaluar — BLOCKED, no INCONCLUSIVE."""
    checks = tuple(SafetyCheck(f"unk-{i}", None, "?") for i in range(5)) + (SafetyCheck("viol", False, "mal"),)
    state, _ = decide_state(checks)
    assert state == "BLOCKED"


# ---------------------------------------------------------------------------
# evaluate(): end-to-end contra el estado real del sistema hoy.
# ---------------------------------------------------------------------------


def test_evaluate_without_mission_blast_radius_leaves_three_checks_not_evaluated(contracts_path, context):
    """Sin `mission_blast_radius` suministrado (el caso por defecto de
    `_input()`), el resultado sigue siendo INCONCLUSIVE —
    runbook_signed/mission_impact_bounded/runtime_trust_valid quedan sin
    evaluar. mission_impact_bounded YA es un hecho suministrable desde
    ADR-061 (Fase K, MissionContext real) — aquí simplemente no se
    suministra, igual que blast_radius_bounded/tool_digest_valid pueden
    quedar sin suministrar. runbook_signed/runtime_trust_valid siguen
    siendo constantes estructurales (Sovereign Root of Trust/
    RuntimeTrustContext no existen)."""
    decision = evaluate(_input(), contracts_path=contracts_path, context=context)
    assert decision.state == "INCONCLUSIVE"
    assert set(decision.not_evaluated) == {"runbook_signed", "mission_impact_bounded", "runtime_trust_valid"}
    assert decision.envelope is None


def test_evaluate_with_mission_blast_radius_supplied_reduces_not_evaluated_to_two(contracts_path, context):
    """ADR-061 (Fase K): con MissionContext real evaluado (mission_blast_radius
    suministrado y no INSUFFICIENT_CONTEXT), mission_impact_bounded deja
    de estar en not_evaluated -- SAFE_TO_EVALUATE sigue sin ser
    alcanzable (runbook_signed/runtime_trust_valid siguen sin existir),
    pero el conjunto de checks sin evaluar se reduce de 3 a 2, medible."""
    decision = evaluate(_input(mission_blast_radius="LOW"), contracts_path=contracts_path, context=context)
    assert decision.state == "INCONCLUSIVE"
    assert set(decision.not_evaluated) == {"runbook_signed", "runtime_trust_valid"}


def test_evaluate_blocks_critical_mission_blast_radius(contracts_path, context):
    """Prueba crítica de K7: mission impact CRITICAL siempre bloquea,
    nunca queda como una nota informativa."""
    decision = evaluate(_input(mission_blast_radius="CRITICAL"), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "mission_impact_bounded" in decision.violated


def test_evaluate_with_insufficient_mission_context_is_not_evaluated_not_bounded(contracts_path, context):
    """INSUFFICIENT_CONTEXT (MissionContext existe como concepto pero no
    se evaluó para este target) se trata exactamente igual que 'no
    suministrado' -- nunca como 'acotado por defecto'."""
    decision = evaluate(_input(mission_blast_radius="INSUFFICIENT_CONTEXT"), contracts_path=contracts_path, context=context)
    assert "mission_impact_bounded" in decision.not_evaluated


def test_evaluate_blocks_irreversible_side_effect_class_unconditionally(contracts_path, context):
    decision = evaluate(_input(side_effect_class="IRREVERSIBLE"), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "no_prohibited_action" in decision.violated


def test_evaluate_blocks_destructive_side_effect_class_unconditionally(contracts_path, context):
    decision = evaluate(_input(side_effect_class="DESTRUCTIVE"), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "no_prohibited_action" in decision.violated


def test_evaluate_blocks_target_outside_allowlist(contracts_path, context):
    decision = evaluate(_input(target_allowlist=frozenset({"deployment/otro"})), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "target_in_scope" in decision.violated


def test_evaluate_blocks_unknown_tool(contracts_path, context):
    decision = evaluate(_input(tool_known=False), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "tool_active" in decision.violated


def test_evaluate_blocks_non_reversible_action(contracts_path, context):
    decision = evaluate(_input(rollback_supported=False), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "action_reversible" in decision.violated
    assert "rollback_available" in decision.violated


def test_evaluate_blocks_target_known_to_not_exist(contracts_path, context):
    decision = evaluate(_input(known_asset_ids=frozenset({"otro-asset"})), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "target_exists" in decision.violated


def test_evaluate_blocks_tampered_tool_digest(contracts_path, context):
    decision = evaluate(_input(tool_digest_valid=False), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "tool_digest_valid" in decision.violated


def test_evaluate_blocks_blast_radius_over_the_max(contracts_path, context):
    decision = evaluate(_input(observed_blast_radius_count=3), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "blast_radius_bounded" in decision.violated


def test_evaluate_blocks_unresolved_critical_drift(contracts_path, context):
    decision = evaluate(_input(no_unresolved_critical_drift=False), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "no_unresolved_critical_drift" in decision.violated


def test_evaluate_blocks_invalid_incident(contracts_path, context):
    bad_incident = _incident()
    del bad_incident["evidence_refs"]  # campo obligatorio del schema real
    decision = evaluate(_input(incident=bad_incident), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert "incident_valid" in decision.violated


def test_evaluate_is_inconclusive_not_optimistic_when_optional_facts_are_omitted(contracts_path, context):
    """Si el llamante no puede suministrar un hecho opcional (p. ej. no
    consultó el inventario de activos), el resultado nunca se rellena
    con un valor optimista — pasa a INCONCLUSIVE, no a SAFE_TO_EVALUATE."""
    decision = evaluate(
        _input(known_asset_ids=None, tool_digest_valid=None, observed_blast_radius_count=None, no_unresolved_critical_drift=None),
        contracts_path=contracts_path,
        context=context,
    )
    assert decision.state == "INCONCLUSIVE"
    assert set(decision.not_evaluated) >= {"target_exists", "tool_digest_valid", "blast_radius_bounded", "no_unresolved_critical_drift"}


def test_a_known_violation_is_reported_even_when_other_facts_are_missing(contracts_path, context):
    decision = evaluate(
        _input(target_allowlist=frozenset({"deployment/otro"}), known_asset_ids=None, tool_digest_valid=None),
        contracts_path=contracts_path,
        context=context,
    )
    assert decision.state == "BLOCKED"  # nunca INCONCLUSIVE cuando ya hay una violación conocida
    assert "target_in_scope" in decision.violated


# ---------------------------------------------------------------------------
# SafetyEnvelope real (solo alcanzable inyectando checks sintéticos —
# ver test_decide_state_all_true_is_safe_to_evaluate arriba para la prueba
# de que la lógica en sí SÍ produce SAFE_TO_EVALUATE cuando corresponde).
# Aquí probamos que, si evaluate() llegara a ese camino, el envelope que
# construye es real y válido contra el schema — para eso forzamos el único
# escenario de hoy en que las 14 comprobaciones dan True: imposible con
# evaluate() tal cual (3 son None por diseño), así que probamos
# _build_envelope_payload directamente, que es la pieza que evaluate()
# invoca en el camino SAFE_TO_EVALUATE.
# ---------------------------------------------------------------------------


def test_build_envelope_payload_produces_a_schema_valid_envelope(contracts_path, context):
    from argos_testing import build_registry, validate_payload
    from safety_kernel import _build_envelope_payload, _run_checks

    inp = _input()
    registry = build_registry(contracts_path)
    checks = _run_checks(inp, contracts_path=contracts_path, registry=registry)
    payload = _build_envelope_payload(inp, checks)
    from argos_envelope import build_envelope

    full_payload = {**build_envelope(context, payload, message_id=payload["envelope_id"]), **payload}
    errors = validate_payload(contracts_path, registry, "safety-envelope", full_payload)
    assert errors == []


def test_envelope_seals_mission_bounds_when_mission_context_was_evaluated(contracts_path, context):
    """K.1: mission_bounds ya no es una constante None -- si el llamante
    evaluó MissionContext, el envelope sella {mission_blast_radius,
    mission_context_hash} para que independent_verifier pueda
    re-verificarlo contra la MISMA referencia."""
    from argos_testing import build_registry
    from safety_kernel import _build_envelope_payload, _run_checks

    inp = _input(mission_blast_radius="LOW", mission_context_hash="sha256:" + "a" * 64)
    registry = build_registry(contracts_path)
    checks = _run_checks(inp, contracts_path=contracts_path, registry=registry)
    payload = _build_envelope_payload(inp, checks)
    assert payload["mission_bounds"] == {"mission_blast_radius": "LOW", "mission_context_hash": "sha256:" + "a" * 64}


def test_envelope_mission_bounds_is_none_when_mission_context_not_evaluated(contracts_path, context):
    from argos_testing import build_registry
    from safety_kernel import _build_envelope_payload, _run_checks

    inp = _input()  # mission_blast_radius=None por defecto
    registry = build_registry(contracts_path)
    checks = _run_checks(inp, contracts_path=contracts_path, registry=registry)
    payload = _build_envelope_payload(inp, checks)
    assert payload["mission_bounds"] is None


def test_envelope_mission_bounds_is_none_for_insufficient_context(contracts_path, context):
    from argos_testing import build_registry
    from safety_kernel import _build_envelope_payload, _run_checks

    inp = _input(mission_blast_radius="INSUFFICIENT_CONTEXT")
    registry = build_registry(contracts_path)
    checks = _run_checks(inp, contracts_path=contracts_path, registry=registry)
    payload = _build_envelope_payload(inp, checks)
    assert payload["mission_bounds"] is None


def test_envelope_respects_max_targets_and_max_blast_radius_constants(contracts_path, context):
    from argos_testing import build_registry
    from safety_kernel import MAX_BLAST_RADIUS, MAX_TARGETS, _build_envelope_payload, _run_checks

    inp = _input()
    registry = build_registry(contracts_path)
    checks = _run_checks(inp, contracts_path=contracts_path, registry=registry)
    payload = _build_envelope_payload(inp, checks)
    assert payload["max_targets"] == MAX_TARGETS == len(payload["target_set"])
    assert payload["max_blast_radius"] == MAX_BLAST_RADIUS


def test_irreversible_tool_gets_empty_allowed_actions_in_the_envelope(contracts_path, context):
    from argos_testing import build_registry
    from safety_kernel import _build_envelope_payload, _run_checks

    inp = _input(side_effect_class="DESTRUCTIVE")
    registry = build_registry(contracts_path)
    checks = _run_checks(inp, contracts_path=contracts_path, registry=registry)
    payload = _build_envelope_payload(inp, checks)
    assert payload["allowed_actions"] == []
    assert set(payload["forbidden_actions"]) == set(inp.tool_modes)


def test_envelope_hash_changes_if_any_field_changes(contracts_path, context):
    from argos_testing import build_registry
    from safety_kernel import _build_envelope_payload, _run_checks

    inp = _input()
    registry = build_registry(contracts_path)
    checks = _run_checks(inp, contracts_path=contracts_path, registry=registry)
    payload_a = _build_envelope_payload(inp, checks)

    inp_b = _input(target="deployment/otro-target")
    checks_b = _run_checks(inp_b, contracts_path=contracts_path, registry=registry)
    payload_b = _build_envelope_payload(inp_b, checks_b)

    assert payload_a["envelope_hash"] != payload_b["envelope_hash"]
    assert payload_a["signature"] != payload_b["signature"]


def test_invalid_safety_envelope_raises_with_real_schema_errors():
    with pytest.raises(TypeError):
        InvalidSafetyEnvelope()  # requiere errors — no debe poder construirse vacío por accidente


# ---------------------------------------------------------------------------
# ActionRequest ⊆ SafetyEnvelope
# ---------------------------------------------------------------------------


def _fake_envelope(**overrides: object) -> dict:
    base = {"target_set": ["deployment/gseg-simulado"], "allowed_actions": ["dry-run"]}
    base.update(overrides)
    return base


def test_action_request_within_envelope_true_when_target_and_action_allowed():
    assert action_request_within_envelope(target="deployment/gseg-simulado", action="dry-run", envelope=_fake_envelope())


def test_action_request_within_envelope_false_for_target_outside_target_set():
    assert not action_request_within_envelope(target="deployment/otro", action="dry-run", envelope=_fake_envelope())


def test_action_request_within_envelope_false_for_action_not_allowed():
    assert not action_request_within_envelope(target="deployment/gseg-simulado", action="execute", envelope=_fake_envelope())
