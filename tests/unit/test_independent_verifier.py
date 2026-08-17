from __future__ import annotations

import pytest
from independent_verifier import (
    InvalidVerificationInput,
    VerificationCheck,
    VerificationCheckInput,
    decide_state,
    verify,
)

pytestmark = pytest.mark.filterwarnings("ignore")


def _incident(**overrides: object) -> dict:
    base: dict[str, object] = {
        "incident_id": "inc-verify-001",
        "evidence_refs": ["fixtures/smoke/security-event/wazuh-alert-001.json"],
    }
    base.update(overrides)
    return base


def _envelope(**overrides: object) -> dict:
    base: dict[str, object] = {
        "incident_ref": "inc-verify-001",
        "evidence_root": None,
        "target_set": ["deployment/gseg-simulado"],
        "allowed_actions": ["dry-run", "execute"],
        "forbidden_actions": [],
        "max_blast_radius": 2,
        "required_runbook": "runbooks/isolate_kubernetes_workload.md",
        "rollback_ref": "rollback/isolate_kubernetes_workload",
        "verification_predicates": ["rollback_supported==True para 'isolate_kubernetes_workload'"],
        "mission_bounds": None,
    }
    base.update(overrides)
    return base


def _input(**overrides: object) -> VerificationCheckInput:
    base: dict[str, object] = {
        "envelope": _envelope(),
        "incident": _incident(),
        "tool_name": "isolate_kubernetes_workload",
        "target": "deployment/gseg-simulado",
        "target_allowlist": frozenset({"deployment/gseg-simulado"}),
        "target_confirmed_live": True,
        "runbook_exists": True,
        "rollback_dry_run_ok": True,
        "observed_blast_radius_count": 1,
    }
    base.update(overrides)
    return VerificationCheckInput(**base)


# ---------------------------------------------------------------------------
# decide_state
# ---------------------------------------------------------------------------


def test_decide_state_all_true_is_verified():
    checks = tuple(VerificationCheck(n, True, "ok") for n in ("a", "b"))
    state, reason = decide_state(checks)
    assert state == "VERIFIED"
    assert "reconfirmaron" in reason


def test_decide_state_any_false_is_rejected_even_with_unevaluated():
    checks = (VerificationCheck("a", True, "ok"), VerificationCheck("b", False, "mal"), VerificationCheck("c", None, "?"))
    state, reason = decide_state(checks)
    assert state == "REJECTED"
    assert "b" in reason


def test_decide_state_none_without_violation_is_inconclusive():
    checks = (VerificationCheck("a", True, "ok"), VerificationCheck("b", None, "?"))
    state, _ = decide_state(checks)
    assert state == "INCONCLUSIVE"


@pytest.mark.parametrize("state", ["REJECTED", "INCONCLUSIVE"])
def test_zero_execute_true_for_both_non_verified_states(state):
    """Literal del prompt: INCONCLUSIVE / REJECTED -> ZERO EXECUTE."""
    from independent_verifier import VerificationDecision

    decision = VerificationDecision(state=state, checks=(), reason="x")
    assert decision.zero_execute is True


def test_zero_execute_false_for_verified():
    from independent_verifier import VerificationDecision

    decision = VerificationDecision(state="VERIFIED", checks=(), reason="x")
    assert decision.zero_execute is False


# ---------------------------------------------------------------------------
# verify(): con todos los hechos independientes reales suministrados.
# ---------------------------------------------------------------------------


def test_verify_with_every_fact_confirmed_is_inconclusive_not_verified():
    """Igual que safety_kernel (ADR-054): incluso con TODOS los hechos
    independientes confirmados, mission_constraints_respected sigue
    siendo None (Mission Context no existe) — VERIFIED nunca es
    alcanzable por ningún checkout real de hoy, solo por decide_state()
    de forma aislada (ver arriba)."""
    decision = verify(_input())
    assert decision.state == "INCONCLUSIVE"
    assert decision.not_evaluated == ("mission_constraints_respected",)
    assert decision.zero_execute is True


def test_verify_without_any_fresh_facts_is_inconclusive_not_verified():
    """Si el llamante no puede re-confirmar nada de forma independiente
    (no re-consultó inventario, runbook ni rollback), el resultado nunca
    hereda el optimismo de safety_kernel — queda INCONCLUSIVE."""
    decision = verify(
        _input(target_confirmed_live=None, runbook_exists=None, rollback_dry_run_ok=None, observed_blast_radius_count=None)
    )
    assert decision.state == "INCONCLUSIVE"
    assert decision.zero_execute is True
    assert set(decision.not_evaluated) >= {"targets_exist", "runbook_exists", "rollback_executable", "blast_radius_bounded", "mission_constraints_respected"}


def test_mission_constraints_respected_is_always_not_evaluated():
    """Mission Context no existe -- ni siquiera con todos los demás
    hechos confirmados, este check queda None (no hay parámetro para
    rellenarlo optimistamente)."""
    decision = verify(_input())
    assert "mission_constraints_respected" in decision.not_evaluated


def test_verify_rejects_when_envelope_target_set_does_not_match_target():
    decision = verify(_input(target="deployment/otro"))
    assert decision.state == "REJECTED"
    assert "preconditions_hold" in decision.violated


def test_verify_rejects_when_target_no_longer_in_allowlist():
    """La allowlist pudo haber cambiado entre que safety_kernel construyó
    el envelope y ahora -- preconditions_hold se re-deriva fresco."""
    decision = verify(_input(target_allowlist=frozenset({"deployment/otro"})))
    assert decision.state == "REJECTED"
    assert "preconditions_hold" in decision.violated


def test_verify_rejects_when_target_confirmed_no_longer_live():
    decision = verify(_input(target_confirmed_live=False))
    assert decision.state == "REJECTED"
    assert "targets_exist" in decision.violated


def test_verify_rejects_when_runbook_does_not_exist():
    decision = verify(_input(runbook_exists=False))
    assert decision.state == "REJECTED"
    assert "runbook_exists" in decision.violated


def test_verify_rejects_when_rollback_dry_run_fails():
    decision = verify(_input(rollback_dry_run_ok=False))
    assert decision.state == "REJECTED"
    assert "rollback_executable" in decision.violated


def test_verify_rejects_when_fresh_blast_radius_exceeds_envelope_ceiling():
    """El envelope declaró max_blast_radius=2; una re-observación de 3
    en verificación debe rechazar, incluso si safety_kernel vio 1 antes."""
    decision = verify(_input(observed_blast_radius_count=3))
    assert decision.state == "REJECTED"
    assert "blast_radius_bounded" in decision.violated


def test_verify_rejects_when_references_do_not_resolve():
    decision = verify(_input(envelope=_envelope(incident_ref="inc-DIFERENTE")))
    assert decision.state == "REJECTED"
    assert "references_resolve" in decision.violated


def test_verify_rejects_when_rollback_ref_does_not_match_tool_name():
    decision = verify(_input(envelope=_envelope(rollback_ref="rollback/otro_tool")))
    assert decision.state == "REJECTED"
    assert "references_resolve" in decision.violated


def test_verify_rejects_incident_with_no_evidence_and_no_evidence_root():
    decision = verify(_input(incident=_incident(evidence_refs=[]), envelope=_envelope(evidence_root=None)))
    assert decision.state == "REJECTED"
    assert "facts_exist" in decision.violated


def test_verify_accepts_evidence_root_alone_without_evidence_refs():
    decision = verify(_input(incident=_incident(evidence_refs=[]), envelope=_envelope(evidence_root="manifest-xyz")))
    assert "facts_exist" not in decision.violated


def test_verify_rejects_envelope_without_verification_predicates():
    decision = verify(_input(envelope=_envelope(verification_predicates=[])))
    assert decision.state == "REJECTED"
    assert "postconditions_measurable" in decision.violated


def test_a_known_violation_is_reported_even_when_other_facts_are_missing():
    decision = verify(_input(target="deployment/otro", target_confirmed_live=None, runbook_exists=None))
    assert decision.state == "REJECTED"  # nunca INCONCLUSIVE con una violación conocida
    assert "preconditions_hold" in decision.violated


def test_verify_raises_on_empty_envelope():
    with pytest.raises(InvalidVerificationInput):
        verify(_input(envelope={}))


def test_verify_uses_real_safety_kernel_envelope_end_to_end(contracts_path, context):
    """Integración real: construye un SafetyEnvelope de verdad con
    safety_kernel y lo pasa a independent_verifier — no un envelope
    sintético a mano."""
    from safety_kernel import SafetyCheckInput, evaluate

    incident = {
        "id": "01J0SAFETY0000000000000002",
        "schema_version": "1.0.0",
        "observed_at": "2026-08-17T09:00:00Z",
        "producer": "correlator",
        "classification": "internal",
        "run_id": "run-safety-002",
        "payload_hash": "sha256:" + "0" * 64,
        "incident_id": "inc-safety-002",
        "member_event_ids": ["evt-1"],
        "timeline": [{"timestamp": "2026-08-17T09:00:00Z", "description": "x"}],
        "entities": [{"type": "asset", "id": "asset-x"}],
        "severity": "high",
        "evidence_refs": ["fixtures/smoke/security-event/wazuh-alert-001.json"],
    }
    recommendation = {
        "recommendation_id": "reco-safety-002",
        "incident_id": incident["incident_id"],
        "alternatives": [{"action": "isolate_kubernetes_workload", "description": "aislar"}],
        "selected_action": "isolate_kubernetes_workload",
        "rationale_refs": incident["evidence_refs"],
        "impact": "x",
        "uncertainty": "baja",
        "rollback_plan": "revertir",
    }
    sk_input = SafetyCheckInput(
        incident=incident,
        recommendation=recommendation,
        target="deployment/gseg-simulado",
        tool_name="isolate_kubernetes_workload",
        tool_modes=("dry-run", "execute"),
        side_effect_class="REVERSIBLE_WRITE",
        rollback_supported=True,
        tool_timeout_seconds=30,
        tool_known=True,
        target_allowlist=frozenset({"deployment/gseg-simulado"}),
        known_asset_ids=frozenset({"deployment/gseg-simulado"}),
        tool_digest_valid=True,
        observed_blast_radius_count=1,
        no_unresolved_critical_drift=True,
    )
    sk_decision = evaluate(sk_input, contracts_path=contracts_path, context=context)
    # El propio safety_kernel nunca llega a SAFE_TO_EVALUATE hoy (ver
    # ADR-054) -- para probar independent_verifier igualmente contra un
    # envelope real, se construye uno directamente con la pieza interna
    # que evaluate() usaría si alcanzara ese estado.
    from safety_kernel import _build_envelope_payload, _run_checks

    checks = _run_checks(sk_input, contracts_path=contracts_path, registry=__import__("argos_testing").build_registry(contracts_path))
    envelope = _build_envelope_payload(sk_input, checks)

    assert sk_decision.state == "INCONCLUSIVE"  # confirma el comportamiento honesto documentado en ADR-054

    verifier_input = VerificationCheckInput(
        envelope=envelope,
        incident=incident,
        tool_name="isolate_kubernetes_workload",
        target="deployment/gseg-simulado",
        target_allowlist=frozenset({"deployment/gseg-simulado"}),
        target_confirmed_live=True,
        runbook_exists=True,
        rollback_dry_run_ok=True,
        observed_blast_radius_count=1,
    )
    decision = verify(verifier_input)
    assert decision.state == "INCONCLUSIVE"  # mission_constraints_respected sigue None, ver ADR-055
    assert decision.zero_execute is True
