from __future__ import annotations

import pytest
from soc_adapter import SOCAdapter, redact_for_tlp


def _incident():
    return {
        "incident_id": "inc-x",
        "severity": "high",
        "timeline": [{"timestamp": "2026-08-12T10:00:00Z", "description": "detalle sensible"}],
        "entities": [{"type": "asset", "id": "a1"}],
        "attack_techniques": ["T1078"],
    }


def test_build_handover_includes_optional_fields_when_provided(contracts_path, context):
    adapter = SOCAdapter(contracts_path, context)
    handover = adapter.build_handover(
        incident=_incident(), residual_risk="bajo", evidence_manifest_ref="ref-1", tlp="CLEAR", iocs=["1.2.3.4"], actions=["a1"]
    )
    assert handover["iocs"] == ["1.2.3.4"]
    assert handover["attack_techniques"] == ["T1078"]


@pytest.mark.parametrize("tlp,expects_iocs", [("RED", False), ("AMBER", False), ("GREEN", False), ("CLEAR", True)])
def test_redact_for_tlp_drops_iocs_below_clear(contracts_path, context, tlp, expects_iocs):
    adapter = SOCAdapter(contracts_path, context)
    handover = adapter.build_handover(
        incident=_incident(), residual_risk="bajo", evidence_manifest_ref="ref-1", tlp="CLEAR", iocs=["1.2.3.4"]
    )
    redacted = redact_for_tlp(handover, tlp)
    assert ("iocs" in redacted) == expects_iocs


def test_red_generalizes_summary_and_timeline(contracts_path, context):
    adapter = SOCAdapter(contracts_path, context)
    handover = adapter.build_handover(incident=_incident(), residual_risk="bajo", evidence_manifest_ref="ref-1", tlp="RED")
    redacted = redact_for_tlp(handover, "RED")
    assert redacted["incident_summary"] != handover["incident_summary"]
    assert all(entry["description"] == "" for entry in redacted["timeline"])


def test_redact_for_tlp_never_mutates_original(contracts_path, context):
    adapter = SOCAdapter(contracts_path, context)
    handover = adapter.build_handover(
        incident=_incident(), residual_risk="bajo", evidence_manifest_ref="ref-1", tlp="CLEAR", iocs=["1.2.3.4"]
    )
    original_summary = handover["incident_summary"]
    redact_for_tlp(handover, "RED")
    assert handover["incident_summary"] == original_summary  # el original no cambió


def test_redact_for_tlp_rejects_unknown_level():
    with pytest.raises(ValueError):
        redact_for_tlp({}, "PURPLE")


def test_required_fields_always_present_even_at_red(contracts_path, context):
    adapter = SOCAdapter(contracts_path, context)
    handover = adapter.build_handover(incident=_incident(), residual_risk="bajo", evidence_manifest_ref="ref-1", tlp="RED")
    redacted = redact_for_tlp(handover, "RED")
    for required in ("case_id", "incident_summary", "timeline", "assets", "residual_risk", "evidence_manifest_ref", "tlp"):
        assert required in redacted
