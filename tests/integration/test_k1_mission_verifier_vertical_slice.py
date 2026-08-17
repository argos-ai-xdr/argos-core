"""Fase K.1: microcierre de Independent Verification consciente de
misión. Prueba las propiedades explícitamente pedidas: consistencia
entre barreras (Safety Kernel / Independent Verifier), consistencia
temporal (la verificación usa el MissionContext sellado en el momento de
la decisión, no un estado de grafo posterior) e integración con la
evidencia real de Fase J — reutilizada, no duplicada.
"""
from __future__ import annotations

import json

from argos_envelope import EnvelopeContext
from argos_testing import build_registry
from evidence_root import build_evidence_root, verify_evidence_root
from evidence_root.transparency_log import TransparencyLog
from evidence_writer import EvidenceWriter, RetentionPolicy
from independent_verifier import VerificationCheckInput, verify
from mission_context import build_mission_context
from mission_context.evidence import _mission_context_hash
from safety_kernel import SafetyCheckInput, _build_envelope_payload, _run_checks, evaluate


def _incident(**overrides):
    base = {
        "id": "01J0K1V0000000000000001",
        "schema_version": "1.0.0",
        "observed_at": "2026-08-17T09:00:00Z",
        "producer": "correlator",
        "classification": "internal",
        "run_id": "run-k1-001",
        "payload_hash": "sha256:" + "0" * 64,
        "incident_id": "inc-k1-001",
        "member_event_ids": ["evt-1"],
        "timeline": [{"timestamp": "2026-08-17T09:00:00Z", "description": "x"}],
        "entities": [{"type": "asset", "id": "asset-x"}],
        "severity": "high",
        "evidence_refs": ["ref-1"],
    }
    base.update(overrides)
    return base


def _sk_input(**overrides):
    base: dict[str, object] = {
        "incident": _incident(),
        "recommendation": {
            "recommendation_id": "reco-k1-001", "incident_id": "inc-k1-001",
            "alternatives": [{"action": "isolate_kubernetes_workload", "description": "aislar"}],
            "selected_action": "isolate_kubernetes_workload", "rationale_refs": ["ref-1"],
            "impact": "x", "uncertainty": "baja", "rollback_plan": "revertir",
        },
        "target": "deployment/gseg-simulado", "tool_name": "isolate_kubernetes_workload",
        "tool_modes": ("dry-run", "execute"), "side_effect_class": "REVERSIBLE_WRITE", "rollback_supported": True,
        "tool_timeout_seconds": 30, "tool_known": True, "target_allowlist": frozenset({"deployment/gseg-simulado"}),
        "known_asset_ids": frozenset({"deployment/gseg-simulado"}), "tool_digest_valid": True,
        "observed_blast_radius_count": 1, "no_unresolved_critical_drift": True,
    }
    base.update(overrides)
    return SafetyCheckInput(**base)


# ---------------------------------------------------------------------------
# Consistencia entre barreras.
# ---------------------------------------------------------------------------


def test_safety_kernel_blocked_never_produces_an_envelope_to_verify(contracts_path, context):
    """Safety Kernel BLOCKED -> Independent Verifier no puede hacer
    ejecutable el camino porque no existe SafetyEnvelope que verificar
    -- propiedad estructural, no una comprobación añadida."""
    decision = evaluate(_sk_input(side_effect_class="DESTRUCTIVE"), contracts_path=contracts_path, context=context)
    assert decision.state == "BLOCKED"
    assert decision.envelope is None


def test_safe_to_evaluate_plus_verifier_rejected_is_zero_execute(contracts_path, context):
    ctx = build_mission_context("asset-x", source_id="s", criticality="high", crown_jewel=True)
    mission_hash = _mission_context_hash(ctx)
    sk_input = _sk_input(mission_blast_radius="LOW", mission_context_hash=mission_hash)
    registry = build_registry(contracts_path)
    checks = _run_checks(sk_input, contracts_path=contracts_path, registry=registry)
    envelope = _build_envelope_payload(sk_input, checks)  # simula SAFE_TO_EVALUATE (evaluate() real nunca llega ahí, ver ADR-054)

    v_decision = verify(
        VerificationCheckInput(
            envelope=envelope, incident=sk_input.incident, tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado", target_allowlist=frozenset({"deployment/gseg-simulado"}),
            target_confirmed_live=True, runbook_exists=True, rollback_dry_run_ok=True, observed_blast_radius_count=1,
            fresh_mission_context_hash=mission_hash, fresh_mission_blast_radius="CRITICAL", unresolved_semantic_conflicts=False,
        )
    )
    assert v_decision.state == "REJECTED"
    assert v_decision.zero_execute is True


def test_safe_to_evaluate_plus_verifier_inconclusive_is_zero_execute(contracts_path, context):
    sk_input = _sk_input(mission_blast_radius="LOW", mission_context_hash="sha256:" + "a" * 64)
    registry = build_registry(contracts_path)
    checks = _run_checks(sk_input, contracts_path=contracts_path, registry=registry)
    envelope = _build_envelope_payload(sk_input, checks)

    v_decision = verify(
        VerificationCheckInput(
            envelope=envelope, incident=sk_input.incident, tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado", target_allowlist=frozenset({"deployment/gseg-simulado"}),
            # target_confirmed_live/runbook_exists/etc. no suministrados -> INCONCLUSIVE
        )
    )
    assert v_decision.state == "INCONCLUSIVE"
    assert v_decision.zero_execute is True


def test_safe_to_evaluate_plus_verifier_verified_is_not_zero_execute_but_still_not_approved(contracts_path, context):
    ctx = build_mission_context("asset-x", source_id="s", criticality="medium", crown_jewel=False)
    mission_hash = _mission_context_hash(ctx)
    sk_input = _sk_input(mission_blast_radius="LOW", mission_context_hash=mission_hash)
    registry = build_registry(contracts_path)
    checks = _run_checks(sk_input, contracts_path=contracts_path, registry=registry)
    envelope = _build_envelope_payload(sk_input, checks)

    v_decision = verify(
        VerificationCheckInput(
            envelope=envelope, incident=sk_input.incident, tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado", target_allowlist=frozenset({"deployment/gseg-simulado"}),
            target_confirmed_live=True, runbook_exists=True, rollback_dry_run_ok=True, observed_blast_radius_count=1,
            fresh_mission_context_hash=mission_hash, fresh_mission_blast_radius="LOW", unresolved_semantic_conflicts=False,
        )
    )
    assert v_decision.state == "VERIFIED"
    assert v_decision.zero_execute is False
    # VERIFIED sigue sin ser una aprobación -- no hay ningún campo de
    # autorización en VerificationDecision, la única vía de aprobación
    # real sigue siendo policy_adapter/Approval (ADR-011).
    assert not hasattr(v_decision, "approved")


# ---------------------------------------------------------------------------
# Consistencia temporal: la verificación usa el MissionContext sellado en
# el momento de la decisión, no un estado posterior.
# ---------------------------------------------------------------------------


def test_verification_uses_the_sealed_mission_context_not_a_later_one(contracts_path, context):
    ctx_t1 = build_mission_context("asset-x", source_id="s", criticality="high", crown_jewel=True)
    hash_t1 = _mission_context_hash(ctx_t1)
    sk_input = _sk_input(mission_blast_radius="LOW", mission_context_hash=hash_t1)
    registry = build_registry(contracts_path)
    checks = _run_checks(sk_input, contracts_path=contracts_path, registry=registry)
    envelope = _build_envelope_payload(sk_input, checks)  # sella hash_t1

    # El "mundo" cambia en T2: el MissionContext real del activo cambió
    # (p. ej. deja de ser crown-jewel).
    ctx_t2 = build_mission_context("asset-x", source_id="s", criticality="low", crown_jewel=False)
    hash_t2 = _mission_context_hash(ctx_t2)
    assert hash_t2 != hash_t1

    # Re-verificar con la referencia FRESCA correcta para T1 (la que
    # realmente sustentó la decisión) sigue validando.
    v_at_t1 = verify(
        VerificationCheckInput(
            envelope=envelope, incident=sk_input.incident, tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado", target_allowlist=frozenset({"deployment/gseg-simulado"}),
            target_confirmed_live=True, runbook_exists=True, rollback_dry_run_ok=True, observed_blast_radius_count=1,
            fresh_mission_context_hash=hash_t1, fresh_mission_blast_radius="LOW", unresolved_semantic_conflicts=False,
        )
    )
    assert "mission_constraints_respected" not in v_at_t1.violated

    # Re-verificar usando por error el hash de T2 (el estado NUEVO) contra
    # el envelope sellado en T1 debe rechazar -- la verificación nunca
    # acepta silenciosamente un MissionContext distinto del que se selló.
    v_wrong_reference = verify(
        VerificationCheckInput(
            envelope=envelope, incident=sk_input.incident, tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado", target_allowlist=frozenset({"deployment/gseg-simulado"}),
            target_confirmed_live=True, runbook_exists=True, rollback_dry_run_ok=True, observed_blast_radius_count=1,
            fresh_mission_context_hash=hash_t2, fresh_mission_blast_radius="LOW", unresolved_semantic_conflicts=False,
        )
    )
    assert v_wrong_reference.state == "REJECTED"
    assert "mission_constraints_respected" in v_wrong_reference.violated


# ---------------------------------------------------------------------------
# Integración con evidencia real de Fase J -- sin mecanismo paralelo.
# ---------------------------------------------------------------------------


def test_verification_result_anchors_into_phase_j_evidence(contracts_path, context):
    ctx = build_mission_context("asset-x", source_id="s", criticality="medium", crown_jewel=False)
    mission_hash = _mission_context_hash(ctx)
    sk_input = _sk_input(mission_blast_radius="LOW", mission_context_hash=mission_hash)
    registry = build_registry(contracts_path)
    checks = _run_checks(sk_input, contracts_path=contracts_path, registry=registry)
    envelope = _build_envelope_payload(sk_input, checks)

    v_decision = verify(
        VerificationCheckInput(
            envelope=envelope, incident=sk_input.incident, tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado", target_allowlist=frozenset({"deployment/gseg-simulado"}),
            target_confirmed_live=True, runbook_exists=True, rollback_dry_run_ok=True, observed_blast_radius_count=1,
            fresh_mission_context_hash=mission_hash, fresh_mission_blast_radius="LOW", unresolved_semantic_conflicts=False,
        )
    )
    assert v_decision.state == "VERIFIED"

    record = {
        "verification_state": v_decision.state,
        "reason": v_decision.reason,
        "mission_context_hash": mission_hash,
        "envelope_id": envelope["envelope_id"],
        "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in v_decision.checks],
    }
    ec = EnvelopeContext(producer="independent-verifier", run_id="run-k1-001")
    writer = EvidenceWriter(contracts_path, ec)
    manifest = writer.write_bytes(json.dumps(record, sort_keys=True).encode("utf-8"), media_type="application/json", retention=RetentionPolicy(policy="365d"))
    root = build_evidence_root([manifest], run_id="run-k1-001", producer="independent-verifier")
    assert verify_evidence_root(root)

    log = TransparencyLog()
    log.append(event_type="EVIDENCE_ROOT_CREATED", object_id=root["root_id"], object_hash=root["root_hash"], run_id="run-k1-001", producer="independent-verifier")
    receipt = log.issue_receipt(root["root_id"])
    assert receipt.event_type == "EVIDENCE_ROOT_CREATED"
    assert log.verify_chain().ok
