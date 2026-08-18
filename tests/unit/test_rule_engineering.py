from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest
from rule_engineering import InvalidRuleId, RuleDeploymentGate, compile_rule_spec_to_xml

_RULE_SPEC = {
    "rule_spec_id": "rulespec-t1",
    "reason": "repeated_suspicious_authentication_activity",
    "parent_rule_sid": "5710",
    "correlation": {"frequency": 8, "timeframe_seconds": 120, "same_source_ip": True, "same_user": False},
    "severity_level": 10,
    "description": "Repeated suspicious authentication activity",
    "mitre_ids": ["T1110"],
    "groups": ["authentication_failure", "brute_force"],
    "investigation_ref": "assess-t1",
}


def test_compile_produces_well_formed_xml_with_expected_fields():
    xml_str = compile_rule_spec_to_xml(_RULE_SPEC, rule_id=100123)
    root = ET.fromstring(xml_str)  # lanza si no es XML bien formado
    assert root.tag == "rule"
    assert root.get("id") == "100123"
    assert root.get("level") == "10"
    assert root.get("frequency") == "8"
    assert root.get("timeframe") == "120"
    assert root.find("if_matched_sid").text == "5710"
    assert root.find("same_source_ip") is not None
    assert root.find("same_user") is None  # same_user=False -> no debe aparecer
    assert root.find("description").text == "Repeated suspicious authentication activity"
    assert [e.text for e in root.find("mitre").findall("id")] == ["T1110"]
    assert root.find("group").text == "authentication_failure,brute_force,"


@pytest.mark.parametrize("rule_id", [99999, 120001, 0, -5])
def test_compile_rejects_rule_id_outside_reserved_range(rule_id):
    with pytest.raises(InvalidRuleId):
        compile_rule_spec_to_xml(_RULE_SPEC, rule_id=rule_id)


@pytest.mark.parametrize("rule_id", [100000, 120000])
def test_compile_accepts_range_boundaries(rule_id):
    compile_rule_spec_to_xml(_RULE_SPEC, rule_id=rule_id)  # no debe lanzar


def test_compile_escapes_description_safely():
    """Robustez real, no solo declarada: una descripción con caracteres
    especiales de XML no rompe el documento ni permite inyectar
    elementos -- ElementTree escapa por construcción, este test lo
    confirma contra el compilador real, no contra ElementTree en
    abstracto."""
    spec = dict(_RULE_SPEC, description="<script>alert(1)</script> & \"quotes\"")
    xml_str = compile_rule_spec_to_xml(spec, rule_id=100123)
    root = ET.fromstring(xml_str)  # si no escapase bien, esto lanzaría ParseError
    assert root.find("description").text == '<script>alert(1)</script> & "quotes"'


def test_compile_without_correlation_omits_frequency_attributes():
    spec = dict(_RULE_SPEC)
    del spec["correlation"]
    xml_str = compile_rule_spec_to_xml(spec, rule_id=100123)
    root = ET.fromstring(xml_str)
    assert root.get("frequency") is None
    assert root.get("timeframe") is None
    assert root.find("same_source_ip") is None


# ---------------------------------------------------------------------------
# RuleDeploymentGate -- AI_DIRECT_RULE_DEPLOYMENT=DENY (ADR-069)
# ---------------------------------------------------------------------------

_CONFIRMED_DECISION = {"decision": "CONFIRMED_THREAT"}
_LOW_VOLUME_BACKTEST = {"max_alerts_per_hour": 5}


def test_deployment_denied_when_soc_decision_is_not_confirmed_threat():
    gate = RuleDeploymentGate()
    result = gate.authorize_deployment(
        rule_spec=_RULE_SPEC, soc_decision={"decision": "MONITOR"},
        backtest_result=_LOW_VOLUME_BACKTEST, durable_approval_available=True,
    )
    assert result.allowed is False
    assert "CONFIRMED_THREAT" in result.reason


def test_deployment_denied_without_backtest_result():
    gate = RuleDeploymentGate()
    result = gate.authorize_deployment(
        rule_spec=_RULE_SPEC, soc_decision=_CONFIRMED_DECISION,
        backtest_result=None, durable_approval_available=True,
    )
    assert result.allowed is False
    assert "backtest" in result.reason.lower()


def test_deployment_denied_when_alert_volume_exceeds_threshold():
    gate = RuleDeploymentGate(max_alerts_per_hour=100)
    result = gate.authorize_deployment(
        rule_spec=_RULE_SPEC, soc_decision=_CONFIRMED_DECISION,
        backtest_result={"max_alerts_per_hour": 50000}, durable_approval_available=True,
    )
    assert result.allowed is False
    assert "alert" in result.reason.lower() or "tormenta" in result.reason.lower()


def test_ai_direct_rule_deployment_is_denied_even_with_confirmed_threat_and_good_backtest():
    """El invariante central de ADR-069: TODAS las demás condiciones
    correctas (SOC confirmó, backtest de bajo volumen) no bastan sin
    durable_approval_available=True -- que hoy SIEMPRE es False en
    cualquier llamada real (CH-07 KNOWN_FAILING, ARG-020 sin cerrar)."""
    gate = RuleDeploymentGate()
    result = gate.authorize_deployment(
        rule_spec=_RULE_SPEC, soc_decision=_CONFIRMED_DECISION,
        backtest_result=_LOW_VOLUME_BACKTEST, durable_approval_available=False,
    )
    assert result.allowed is False
    assert "AI_DIRECT_RULE_DEPLOYMENT" in result.reason


def test_deployment_authorized_only_when_every_condition_holds():
    gate = RuleDeploymentGate()
    result = gate.authorize_deployment(
        rule_spec=_RULE_SPEC, soc_decision=_CONFIRMED_DECISION,
        backtest_result=_LOW_VOLUME_BACKTEST, durable_approval_available=True,
    )
    assert result.allowed is True
