from __future__ import annotations

import pytest
from investigator import (
    InvalidContextLevel,
    InvalidThreatAssessment,
    build_threat_assessment,
    plan_next_context_level,
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
