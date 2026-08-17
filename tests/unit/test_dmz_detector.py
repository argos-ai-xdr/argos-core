from __future__ import annotations

import dataclasses

import pytest
from argos_testing import build_registry, validate_payload
from dmz_detector import Baseline, DetectedAnomaly, FlowRecord, InvalidSourceMode, detect_anomalies
from normalizer import Normalizer, RawEvent

BASELINE = Baseline(
    authorized_destinations=frozenset({"evidence-writer.argos-xdr.svc.cluster.local"}),
    max_bytes_per_destination={"evidence-writer.argos-xdr.svc.cluster.local": 5_000_000},
)

_DEFAULT_FLOW = FlowRecord(
    native_ref="hubble://flow/1",
    source="asset-gseg-01",
    destination="evidence-writer.argos-xdr.svc.cluster.local",
    destination_is_external=False,
    port=8080,
    protocol="TCP",
    bytes_transferred=1_000,
    verdict="ALLOWED",
    source_mode="EMULATED",
)


def _flow(**overrides: object) -> FlowRecord:
    return dataclasses.replace(_DEFAULT_FLOW, **overrides)  # type: ignore[arg-type]


def test_authorized_low_volume_flow_produces_no_anomaly():
    assert detect_anomalies([_flow()], BASELINE) == []


def test_unauthorized_external_destination_is_critical():
    flow = _flow(destination="185.220.101.1", destination_is_external=True)
    anomalies = detect_anomalies([flow], BASELINE)
    assert len(anomalies) == 1
    assert anomalies[0].event.severity_native == "critical"
    assert anomalies[0].event.asset_id == "asset-gseg-01"


def test_unauthorized_internal_destination_is_high_not_critical():
    flow = _flow(destination="internal-debug-svc", destination_is_external=False)
    anomalies = detect_anomalies([flow], BASELINE)
    assert anomalies[0].event.severity_native == "high"


def test_volume_spike_to_authorized_destination_is_flagged():
    flow = _flow(bytes_transferred=50_000_000)  # muy por encima del umbral de 5MB
    anomalies = detect_anomalies([flow], BASELINE)
    assert len(anomalies) == 1


def test_denied_flow_is_not_silently_dropped():
    """Regresión conceptual (C-08.UC5: 'anomalía crítica golden omitida =
    0'): un intento de exfiltración BLOQUEADO por NetworkPolicy sigue
    siendo señal real que investigar, no 'sin anomalía' solo porque ya
    fue contenido."""
    flow = _flow(destination="185.220.101.1", destination_is_external=True, verdict="DENIED")
    anomalies = detect_anomalies([flow], BASELINE)
    assert len(anomalies) == 1
    assert anomalies[0].event.severity_native == "critical"


def test_multiple_flows_produce_independent_events():
    flows = [
        _flow(native_ref="hubble://flow/1"),
        _flow(native_ref="hubble://flow/2", destination="185.220.101.1", destination_is_external=True),
    ]
    anomalies = detect_anomalies(flows, BASELINE)
    assert len(anomalies) == 1  # solo el segundo es anómalo


def test_source_mode_is_carried_through_to_the_detected_anomaly():
    """Propuesta v0.6.25.4 (13.13): la aceptación exige 'source_mode
    correcto' — nunca se debe perder si el dato viene de la DMZ real o de
    un replay contractual."""
    flow = _flow(destination="185.220.101.1", destination_is_external=True, source_mode="REAL_CONNECTOR")
    anomalies = detect_anomalies([flow], BASELINE)
    assert anomalies[0].source_mode == "REAL_CONNECTOR"

    flow_emulated = _flow(
        native_ref="hubble://flow/2", destination="185.220.101.1", destination_is_external=True, source_mode="EMULATED"
    )
    anomalies_emulated = detect_anomalies([flow_emulated], BASELINE)
    assert anomalies_emulated[0].source_mode == "EMULATED"


def test_invalid_source_mode_is_rejected_not_silently_accepted():
    """Nunca se debe afirmar REAL_CONNECTOR (o cualquier otro valor) que
    no sea uno de los dos modos reconocidos — un typo o un valor
    inventado no debe colarse como si fuera válido."""
    flow = _flow(destination="185.220.101.1", destination_is_external=True, source_mode="PRODUCTION")
    with pytest.raises(InvalidSourceMode):
        detect_anomalies([flow], BASELINE)


def test_anomaly_feeds_the_real_normalizer_pipeline_and_carries_source_mode(contracts_path, context):
    """Prueba de integración real: el RawEvent que produce dmz-detector
    debe ser exactamente lo que normalizer.Normalizer espera y producir un
    SecurityEvent válido contra el schema real — no un objeto compatible
    'a ojo'. source_mode se añade al payload ya validado
    (additionalProperties: true en security-event/v1.schema.json, no rompe
    el contrato) y debe sobrevivir intacto."""
    flow = _flow(destination="185.220.101.1", destination_is_external=True, source_mode="REAL_CONNECTOR")
    anomalies = detect_anomalies([flow], BASELINE)
    assert len(anomalies) == 1

    normalizer = Normalizer(contracts_path, context)
    result = normalizer.process(anomalies[0].event)
    payload = {**result.payload, "source_mode": anomalies[0].source_mode}

    assert payload["source"] == "dmz-detector"
    assert payload["severity_normalized"] == "critical"
    assert payload["severity_native"] == "critical"
    assert payload["source_mode"] == "REAL_CONNECTOR"

    registry = build_registry(contracts_path)
    errors = validate_payload(contracts_path, registry, "security-event", payload)
    assert errors == []


def test_detected_anomaly_wraps_a_real_raw_event():
    anomalies = detect_anomalies([_flow(destination="185.220.101.1", destination_is_external=True)], BASELINE)
    assert isinstance(anomalies[0], DetectedAnomaly)
    assert isinstance(anomalies[0].event, RawEvent)
