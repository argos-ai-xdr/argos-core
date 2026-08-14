from __future__ import annotations

import dataclasses

from dmz_detector import Baseline, FlowRecord, detect_anomalies
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
)


def _flow(**overrides: object) -> FlowRecord:
    return dataclasses.replace(_DEFAULT_FLOW, **overrides)  # type: ignore[arg-type]


def test_authorized_low_volume_flow_produces_no_anomaly():
    assert detect_anomalies([_flow()], BASELINE) == []


def test_unauthorized_external_destination_is_critical():
    flow = _flow(destination="185.220.101.1", destination_is_external=True)
    events = detect_anomalies([flow], BASELINE)
    assert len(events) == 1
    assert events[0].severity_native == "critical"
    assert events[0].asset_id == "asset-gseg-01"


def test_unauthorized_internal_destination_is_high_not_critical():
    flow = _flow(destination="internal-debug-svc", destination_is_external=False)
    events = detect_anomalies([flow], BASELINE)
    assert events[0].severity_native == "high"


def test_volume_spike_to_authorized_destination_is_flagged():
    flow = _flow(bytes_transferred=50_000_000)  # muy por encima del umbral de 5MB
    events = detect_anomalies([flow], BASELINE)
    assert len(events) == 1


def test_denied_flow_is_not_silently_dropped():
    """Regresión conceptual (C-08.UC5: 'anomalía crítica golden omitida =
    0'): un intento de exfiltración BLOQUEADO por NetworkPolicy sigue
    siendo señal real que investigar, no 'sin anomalía' solo porque ya
    fue contenido."""
    flow = _flow(destination="185.220.101.1", destination_is_external=True, verdict="DENIED")
    events = detect_anomalies([flow], BASELINE)
    assert len(events) == 1
    assert events[0].severity_native == "critical"


def test_multiple_flows_produce_independent_events():
    flows = [
        _flow(native_ref="hubble://flow/1"),
        _flow(native_ref="hubble://flow/2", destination="185.220.101.1", destination_is_external=True),
    ]
    events = detect_anomalies(flows, BASELINE)
    assert len(events) == 1  # solo el segundo es anómalo


def test_anomaly_feeds_the_real_normalizer_pipeline(contracts_path, context):
    """Prueba de integración real: el RawEvent que produce dmz-detector
    debe ser exactamente lo que normalizer.Normalizer espera y producir un
    SecurityEvent válido contra el schema real — no un objeto compatible
    'a ojo'."""
    flow = _flow(destination="185.220.101.1", destination_is_external=True)
    events = detect_anomalies([flow], BASELINE)
    assert len(events) == 1

    normalizer = Normalizer(contracts_path, context)
    result = normalizer.process(events[0])
    assert result.payload["source"] == "dmz-detector"
    assert result.payload["severity_normalized"] == "critical"
    assert result.payload["severity_native"] == "critical"


def test_raw_event_type_matches_normalizer_expectation():
    events = detect_anomalies([_flow(destination="185.220.101.1", destination_is_external=True)], BASELINE)
    assert isinstance(events[0], RawEvent)
