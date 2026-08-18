from __future__ import annotations

import datetime

import pytest
from correlator import build_incident_payload, dedupe_by_correlation_key, group_by_asset_and_window


def _event(event_id, asset_id, observed_at, severity, source="wazuh", correlation_key=None):
    event = {
        "id": f"env-{event_id}",
        "event_id": event_id,
        "asset_id": asset_id,
        "observed_at": observed_at,
        "severity_normalized": severity,
        "source": source,
    }
    if correlation_key is not None:
        event["correlation"] = {"correlation_key": correlation_key}
    return event


def test_groups_close_events_of_same_asset():
    events = [
        _event("e1", "a1", "2026-08-12T10:00:00Z", "high"),
        _event("e2", "a1", "2026-08-12T10:02:00Z", "critical"),
    ]
    groups = group_by_asset_and_window(events, datetime.timedelta(minutes=10))
    assert len(groups) == 1
    assert {e["event_id"] for e in groups[0]} == {"e1", "e2"}


def test_splits_events_beyond_window():
    events = [
        _event("e1", "a1", "2026-08-12T10:00:00Z", "high"),
        _event("e2", "a1", "2026-08-12T11:30:00Z", "low"),
    ]
    groups = group_by_asset_and_window(events, datetime.timedelta(minutes=10))
    assert len(groups) == 2


def test_different_assets_never_grouped_together():
    events = [
        _event("e1", "a1", "2026-08-12T10:00:00Z", "high"),
        _event("e2", "a2", "2026-08-12T10:00:01Z", "high"),
    ]
    groups = group_by_asset_and_window(events, datetime.timedelta(minutes=10))
    assert len(groups) == 2


def test_incident_severity_is_max_of_members(contracts_path, context):
    events = [_event("e1", "a1", "2026-08-12T10:00:00Z", "low"), _event("e2", "a1", "2026-08-12T10:01:00Z", "critical")]
    incident = build_incident_payload(contracts_path, context, events)
    assert incident["severity"] == "critical"


def test_incident_confidence_defaults_to_low(contracts_path, context):
    events = [_event("e1", "a1", "2026-08-12T10:00:00Z", "high")]
    incident = build_incident_payload(contracts_path, context, events)
    assert incident["confidence"] == "low"


def test_incident_requires_at_least_one_event(contracts_path, context):
    with pytest.raises(ValueError):
        build_incident_payload(contracts_path, context, [])


def test_incident_evidence_refs_point_to_member_envelope_ids(contracts_path, context):
    events = [_event("e1", "a1", "2026-08-12T10:00:00Z", "high")]
    incident = build_incident_payload(contracts_path, context, events)
    assert incident["evidence_refs"] == ["env-e1"]


def test_incident_entities_deduplicate_same_asset(contracts_path, context):
    """Regresión: entities listaba la misma entidad una vez por cada evento
    miembro, en vez de una vez por asset. group_by_asset_and_window agrupa
    precisamente por asset_id, así que el caso normal — no el raro — es que
    varios eventos miembro compartan asset_id (3 eventos del mismo asset
    producían 3 entidades idénticas)."""
    events = [
        _event("e1", "a1", "2026-08-12T10:00:00Z", "high"),
        _event("e2", "a1", "2026-08-12T10:00:30Z", "medium"),
        _event("e3", "a1", "2026-08-12T10:01:00Z", "low"),
    ]
    incident = build_incident_payload(contracts_path, context, events)
    assert incident["entities"] == [{"type": "asset", "id": "a1"}]


def test_incident_entities_include_each_distinct_asset_once(contracts_path, context):
    events = [
        _event("e1", "a1", "2026-08-12T10:00:00Z", "high"),
        _event("e2", "a2", "2026-08-12T10:00:01Z", "high"),
        _event("e3", "a1", "2026-08-12T10:00:02Z", "high"),
    ]
    incident = build_incident_payload(contracts_path, context, events)
    assert incident["entities"] == [{"type": "asset", "id": "a1"}, {"type": "asset", "id": "a2"}]


# ---------------------------------------------------------------------------
# dedupe_by_correlation_key (2026-08-18, ARG-015/016): un mismo ataque real
# puede producir muchas alertas nativas para la misma actividad (caso Falco
# real, una alerta por subproceso Linux -- correo del equipo XDR/Wazuh). No
# se debe convertir cada una en un Incident independiente, pero tampoco
# fusionar dos ataques distintos por exceso de deduplicación.
# ---------------------------------------------------------------------------


def test_dedupe_collapses_many_events_sharing_correlation_key():
    """El caso real que motivó esto: 50 eventos Falco (uno por subproceso)
    de la MISMA actividad de ataque colapsan en un único evento
    representativo, sin perder ninguna referencia original."""
    events = [
        _event(f"falco-{i}", "a1", f"2026-08-18T10:00:{i:02d}Z", "high", source="falco", correlation_key="attack-xyz")
        for i in range(50)
    ]
    collapsed = dedupe_by_correlation_key(events)
    assert len(collapsed) == 1
    assert collapsed[0]["correlation"]["occurrence_count"] == 50
    assert collapsed[0]["correlation"]["first_seen"] == "2026-08-18T10:00:00Z"
    assert collapsed[0]["correlation"]["last_seen"] == "2026-08-18T10:00:49Z"
    assert collapsed[0]["correlation"]["related_event_refs"] == [f"env-falco-{i}" for i in range(50)]
    assert collapsed[0]["event_id"] == "falco-0"  # base = el más antiguo del grupo, no uno fabricado


def test_dedupe_does_not_merge_two_distinct_attacks():
    """Dos ataques reales y distintos, cada uno con su propia
    correlation_key, sobre el mismo asset y ventana temporal cercana --
    NO deben fusionarse en uno solo."""
    events = [
        _event("e1", "a1", "2026-08-18T10:00:00Z", "high", correlation_key="attack-A"),
        _event("e2", "a1", "2026-08-18T10:00:01Z", "high", correlation_key="attack-A"),
        _event("e3", "a1", "2026-08-18T10:00:02Z", "critical", correlation_key="attack-B"),
    ]
    collapsed = dedupe_by_correlation_key(events)
    assert len(collapsed) == 2
    by_key = {c["correlation"]["correlation_key"]: c for c in collapsed}
    assert by_key["attack-A"]["correlation"]["occurrence_count"] == 2
    assert by_key["attack-B"]["correlation"]["occurrence_count"] == 1


def test_dedupe_leaves_events_without_correlation_key_untouched_and_in_place():
    events = [
        _event("e1", "a1", "2026-08-18T10:00:00Z", "high"),  # sin correlation_key
        _event("e2", "a1", "2026-08-18T10:00:01Z", "high", correlation_key="attack-A"),
        _event("e3", "a1", "2026-08-18T10:00:02Z", "high", correlation_key="attack-A"),
        _event("e4", "a1", "2026-08-18T10:00:03Z", "low"),  # sin correlation_key
    ]
    collapsed = dedupe_by_correlation_key(events)
    # Orden por primera aparición: e1 (passthrough), grupo attack-A (en la
    # posición de su primera aparición, e2), e4 (passthrough) -- nunca todo
    # lo colapsado empujado al final.
    assert [e["event_id"] for e in collapsed] == ["e1", "e2", "e4"]
    assert "correlation" not in collapsed[0]
    assert collapsed[1]["correlation"]["occurrence_count"] == 2


def test_dedupe_then_group_produces_one_incident_worth_of_events_for_50_subprocess_alerts(contracts_path, context):
    """Integración end-to-end del caso real de Georgi: 50 alertas Falco de
    subproceso de la misma actividad -> dedupe_by_correlation_key ->
    group_by_asset_and_window -> un único grupo -> un único Incident, no 50."""
    events = [
        _event(f"falco-{i}", "a1", f"2026-08-18T10:00:{i:02d}Z", "high", source="falco", correlation_key="attack-xyz")
        for i in range(50)
    ]
    collapsed = dedupe_by_correlation_key(events)
    groups = group_by_asset_and_window(collapsed, datetime.timedelta(minutes=10))
    assert len(groups) == 1

    incident = build_incident_payload(contracts_path, context, groups[0])
    assert incident["member_event_ids"] == ["falco-0"]
    assert len(incident["evidence_refs"]) == 1
