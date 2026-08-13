"""Reproduce un fragmento del escenario ARGOS-CYB-01 a partir de los
fixtures REALES de argos-contracts-scenarios/fixtures/smoke/ (no datos
inventados en el test) — mismo espíritu que argos-validation/suites/
argos-cyb-01/, pero ejercitando los servicios reales de este repositorio en
vez de solo evaluar fixtures estáticos.
"""
from __future__ import annotations

from argos_testing import load_fixture
from correlator import build_incident_payload
from recommendation import DeterministicFallbackEngine


def test_replay_smoke_security_event_through_correlator_and_recommendation(contracts_path, context):
    security_event = load_fixture(contracts_path, "smoke", "security-event", "wazuh-alert-001.json")
    assert security_event["asset_id"] == "asset-gseg-01"  # activo crítico de la ficha (5.1)

    incident = build_incident_payload(contracts_path, context, [security_event])
    assert incident["severity"] == security_event["severity_normalized"]
    assert incident["member_event_ids"] == [security_event["event_id"]]

    reco = DeterministicFallbackEngine(contracts_path, context).generate(incident)
    # El fixture es severidad 'high' (ver wazuh-alert-001.json) -> runbook de contención
    assert reco["selected_action"] == "isolate_kubernetes_workload"
