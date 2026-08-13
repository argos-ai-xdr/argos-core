from __future__ import annotations

import pytest
from normalizer import Normalizer, RawEvent, RejectedEvent, normalize_severity


@pytest.mark.parametrize(
    "source,native,expected",
    [
        ("wazuh", "2", "low"),
        ("wazuh", "8", "medium"),
        ("wazuh", "11", "high"),
        ("wazuh", "15", "critical"),
        ("wazuh", "not-a-number", "medium"),  # fallback conservador, no crash
        ("falco", "Warning", "medium"),
        ("falco", "Emergency", "critical"),
        ("falco", "unknown-priority", "medium"),
        ("unknown-source", "whatever", "medium"),
        ("wazuh", "high", "high"),  # ya normalizado: se respeta tal cual
    ],
)
def test_normalize_severity(source, native, expected):
    assert normalize_severity(source, native) == expected


def test_normalizer_produces_schema_valid_event(contracts_path, context):
    normalizer = Normalizer(contracts_path, context)
    result = normalizer.process(RawEvent(source="wazuh", native_ref="wazuh://alert/1", severity_native="12"))
    assert result.payload["event_id"] == result.event_id
    assert result.payload["severity_normalized"] == "high"


def test_normalizer_deduplicates_by_source_and_native_ref(contracts_path, context):
    normalizer = Normalizer(contracts_path, context)
    raw = RawEvent(source="wazuh", native_ref="wazuh://alert/1", severity_native="5")
    normalizer.process(raw)
    with pytest.raises(RejectedEvent):
        normalizer.process(raw)


def test_normalizer_allows_retry_after_rejected_schema(contracts_path, context, monkeypatch):
    """Un evento rechazado por schema no debe consumir el dedup — debe
    poder reintentarse una vez corregido. Forzamos el rechazo con
    monkeypatch porque, con el schema actual, ningún RawEvent válido llega
    a fallar la validación por sí solo (no hay minLength en los campos de
    texto) — este test aísla esa rama concreta a propósito."""
    normalizer = Normalizer(contracts_path, context)
    raw = RawEvent(source="wazuh", native_ref="wazuh://alert/2", severity_native="5")
    dedup_key = (raw.source, raw.native_ref)

    monkeypatch.setattr("normalizer.validate_payload", lambda *a, **k: ["forzado: campo inválido"])
    with pytest.raises(RejectedEvent):
        normalizer.process(raw)
    assert dedup_key not in normalizer._seen  # el rechazo no dejó consumido el dedup

    monkeypatch.undo()
    result = normalizer.process(raw)  # ahora sí debe poder procesarse
    assert result.event_id
    assert dedup_key in normalizer._seen
