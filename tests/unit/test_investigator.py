from __future__ import annotations

import datetime

import pytest
from investigator import (
    InvalidContextLevel,
    InvalidThreatAssessment,
    build_threat_assessment,
    is_signal_tombstoned,
    plan_next_context_level,
    should_trigger_new_investigation,
)


def test_first_call_always_returns_l0():
    assert plan_next_context_level(None, hypothesis_still_open=True) == "L0"
    assert plan_next_context_level(None, hypothesis_still_open=False) == "L0"


def test_progresses_through_all_levels_while_hypothesis_stays_open():
    level = plan_next_context_level(None, hypothesis_still_open=True)
    sequence = [level]
    while level is not None:
        level = plan_next_context_level(level, hypothesis_still_open=True)
        if level is not None:
            sequence.append(level)
    assert sequence == ["L0", "L1", "L2", "L3", "L4", "L5"]


def test_l5_is_the_ceiling_no_implicit_l6():
    assert plan_next_context_level("L5", hypothesis_still_open=True) is None


@pytest.mark.parametrize("level", ["L0", "L1", "L2", "L3", "L4", "L5"])
def test_resolved_hypothesis_stops_escalation_at_any_level(level):
    assert plan_next_context_level(level, hypothesis_still_open=False) is None


def test_unknown_level_raises():
    with pytest.raises(InvalidContextLevel):
        plan_next_context_level("L99", hypothesis_still_open=True)


# ---------------------------------------------------------------------------
# build_threat_assessment
# ---------------------------------------------------------------------------


def test_threat_assessment_requires_investigation_refs():
    with pytest.raises(ValueError):
        build_threat_assessment(
            None, None, investigation_refs=[], conclusion="SUSPICIOUS", evidence_refs=["ev-1"],  # type: ignore[arg-type]
        )


def test_threat_assessment_requires_evidence_refs():
    with pytest.raises(ValueError):
        build_threat_assessment(
            None, None, investigation_refs=["inv-1"], conclusion="SUSPICIOUS", evidence_refs=[],  # type: ignore[arg-type]
        )


def test_threat_assessment_builds_valid_payload(contracts_path, context):
    assessment = build_threat_assessment(
        contracts_path, context,
        investigation_refs=["inv-1", "inv-2"],
        conclusion="LIKELY_THREAT",
        evidence_refs=["ev-1", "ev-2"],
        attack_techniques=["T1078"],
        affected_assets=["asset-1"],
        hypotheses=["Escalada de privilegios"],
        unknowns=["Sin confirmar autorización del usuario"],
    )
    assert assessment["conclusion"] == "LIKELY_THREAT"
    assert assessment["investigation_refs"] == ["inv-1", "inv-2"]
    assert assessment["evidence_refs"] == ["ev-1", "ev-2"]
    assert assessment["mission_impact"] is None


def test_threat_assessment_rejects_invalid_conclusion(contracts_path, context):
    with pytest.raises(InvalidThreatAssessment):
        build_threat_assessment(
            contracts_path, context,
            investigation_refs=["inv-1"], conclusion="MAYBE_IDK", evidence_refs=["ev-1"],
        )


# ---------------------------------------------------------------------------
# should_trigger_new_investigation (ADR-070, DE-19): protección contra
# bucle recursivo AI Candidate -> Kafka -> AI Candidate -> ...
# ---------------------------------------------------------------------------


def test_argos_candidate_never_triggers_new_investigation():
    signal = {"source_mode": "CANDIDATE", "origin_system": "argos-ai"}
    assert should_trigger_new_investigation(signal) is False


@pytest.mark.parametrize(
    "signal",
    [
        {"source_mode": "REAL", "origin_system": "wazuh"},
        {"source_mode": "SYNTHETIC", "origin_system": "idlab-generator"},
        {"source_mode": "CANDIDATE", "origin_system": "wazuh"},  # CANDIDATE de OTRO origen -- sí dispara
        {"source_mode": "REAL"},  # sin origin_system -- no es el caso recursivo
    ],
)
def test_other_combinations_trigger_investigation_normally(signal):
    assert should_trigger_new_investigation(signal) is True


# ---------------------------------------------------------------------------
# is_signal_tombstoned (ADR-070, DE-23): supresión acotada, nunca global.
# ---------------------------------------------------------------------------


def _tombstone(*, entity_refs, signal_signature, valid_from, valid_until):
    return {
        "entity_refs": entity_refs, "signal_signature": signal_signature,
        "valid_from": valid_from, "valid_until": valid_until,
    }


def test_matching_active_tombstone_suppresses():
    now = datetime.datetime(2026, 8, 18, 13, 0, tzinfo=datetime.UTC)
    tombstones = [_tombstone(
        entity_refs=["asset-1"], signal_signature="sig-a",
        valid_from="2026-08-18T12:00:00+00:00", valid_until="2026-08-25T12:00:00+00:00",
    )]
    assert is_signal_tombstoned(
        entity_refs=["asset-1"], signal_signature="sig-a", tombstones=tombstones, now=now
    ) is True


def test_expired_tombstone_no_longer_suppresses():
    now = datetime.datetime(2026, 9, 1, 0, 0, tzinfo=datetime.UTC)  # después de valid_until
    tombstones = [_tombstone(
        entity_refs=["asset-1"], signal_signature="sig-a",
        valid_from="2026-08-18T12:00:00+00:00", valid_until="2026-08-25T12:00:00+00:00",
    )]
    assert is_signal_tombstoned(
        entity_refs=["asset-1"], signal_signature="sig-a", tombstones=tombstones, now=now
    ) is False


def test_different_signal_signature_is_not_suppressed():
    now = datetime.datetime(2026, 8, 18, 13, 0, tzinfo=datetime.UTC)
    tombstones = [_tombstone(
        entity_refs=["asset-1"], signal_signature="sig-a",
        valid_from="2026-08-18T12:00:00+00:00", valid_until="2026-08-25T12:00:00+00:00",
    )]
    assert is_signal_tombstoned(
        entity_refs=["asset-1"], signal_signature="sig-DIFFERENT", tombstones=tombstones, now=now
    ) is False


def test_no_entity_overlap_is_not_suppressed():
    """Un tombstone acotado a asset-1 nunca suprime una señal sobre
    asset-2, aunque comparta signal_signature -- nunca supresión global."""
    now = datetime.datetime(2026, 8, 18, 13, 0, tzinfo=datetime.UTC)
    tombstones = [_tombstone(
        entity_refs=["asset-1"], signal_signature="sig-a",
        valid_from="2026-08-18T12:00:00+00:00", valid_until="2026-08-25T12:00:00+00:00",
    )]
    assert is_signal_tombstoned(
        entity_refs=["asset-2"], signal_signature="sig-a", tombstones=tombstones, now=now
    ) is False


def test_no_tombstones_is_never_suppressed():
    now = datetime.datetime(2026, 8, 18, 13, 0, tzinfo=datetime.UTC)
    assert is_signal_tombstoned(
        entity_refs=["asset-1"], signal_signature="sig-a", tombstones=[], now=now
    ) is False
