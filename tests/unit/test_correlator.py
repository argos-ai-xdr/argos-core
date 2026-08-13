from __future__ import annotations

import datetime

import pytest
from correlator import build_incident_payload, group_by_asset_and_window


def _event(event_id, asset_id, observed_at, severity, source="wazuh"):
    return {
        "id": f"env-{event_id}",
        "event_id": event_id,
        "asset_id": asset_id,
        "observed_at": observed_at,
        "severity_normalized": severity,
        "source": source,
    }


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
