from __future__ import annotations

from rule_engineering.backtest import FakeEventStore, run_backtest

_RULE_SPEC_WITH_CORRELATION = {
    "parent_rule_sid": "5710",
    "correlation": {"frequency": 3, "timeframe_seconds": 120, "same_source_ip": True, "same_user": False},
}

_RULE_SPEC_WITHOUT_CORRELATION = {"parent_rule_sid": "5710", "correlation": {}}


def _event(rule_id, asset_id, observed_at, *, source_ip="1.2.3.4", user="u1"):
    return {"wazuh_rule_id": rule_id, "asset_id": asset_id, "source_ip": source_ip, "user": user, "observed_at": observed_at}


def test_only_matching_rule_id_counts():
    store = FakeEventStore(events=[
        _event("5710", "a1", "2026-08-11T10:00:00Z"),
        _event("5710", "a1", "2026-08-11T10:00:10Z"),
        _event("5710", "a1", "2026-08-11T10:00:20Z"),
        _event("9999", "a1", "2026-08-11T10:00:15Z"),  # otra regla -- no cuenta
    ])
    result = run_backtest(_RULE_SPEC_WITH_CORRELATION, store, window_days=7)
    assert result.events_matched == 3


def test_frequency_threshold_determines_estimated_alerts():
    # 3 eventos en la misma ventana con frequency=3 -> 1 alerta estimada.
    store = FakeEventStore(events=[
        _event("5710", "a1", "2026-08-11T10:00:00Z"),
        _event("5710", "a1", "2026-08-11T10:00:10Z"),
        _event("5710", "a1", "2026-08-11T10:00:20Z"),
    ])
    result = run_backtest(_RULE_SPEC_WITH_CORRELATION, store, window_days=7)
    assert result.estimated_alerts == 1


def test_below_frequency_threshold_produces_no_alerts():
    # Solo 2 eventos, frequency=3 -> 0 alertas estimadas.
    store = FakeEventStore(events=[
        _event("5710", "a1", "2026-08-11T10:00:00Z"),
        _event("5710", "a1", "2026-08-11T10:00:10Z"),
    ])
    result = run_backtest(_RULE_SPEC_WITH_CORRELATION, store, window_days=7)
    assert result.estimated_alerts == 0


def test_different_source_ips_do_not_group_together_when_same_source_ip_required():
    store = FakeEventStore(events=[
        _event("5710", "a1", "2026-08-11T10:00:00Z", source_ip="1.1.1.1"),
        _event("5710", "a1", "2026-08-11T10:00:10Z", source_ip="2.2.2.2"),
        _event("5710", "a1", "2026-08-11T10:00:20Z", source_ip="1.1.1.1"),
    ])
    result = run_backtest(_RULE_SPEC_WITH_CORRELATION, store, window_days=7)
    # Solo 2 eventos comparten IP (1.1.1.1) -- por debajo de frequency=3.
    assert result.estimated_alerts == 0


def test_gap_beyond_timeframe_splits_groups():
    store = FakeEventStore(events=[
        _event("5710", "a1", "2026-08-11T10:00:00Z"),
        _event("5710", "a1", "2026-08-11T10:00:10Z"),
        _event("5710", "a1", "2026-08-11T10:10:00Z"),  # >120s de hueco -> grupo nuevo
    ])
    result = run_backtest(_RULE_SPEC_WITH_CORRELATION, store, window_days=7)
    assert result.estimated_alerts == 0  # ningún grupo alcanza frequency=3


def test_without_correlation_every_matched_event_is_an_alert():
    store = FakeEventStore(events=[
        _event("5710", "a1", "2026-08-11T10:00:00Z"),
        _event("5710", "a2", "2026-08-11T10:05:00Z"),
    ])
    result = run_backtest(_RULE_SPEC_WITHOUT_CORRELATION, store, window_days=7)
    assert result.estimated_alerts == 2


def test_unique_assets_and_users_are_counted():
    store = FakeEventStore(events=[
        _event("5710", "a1", "2026-08-11T10:00:00Z", user="alice"),
        _event("5710", "a1", "2026-08-11T10:05:00Z", user="bob"),
        _event("5710", "a2", "2026-08-11T10:10:00Z", user="alice"),
    ])
    result = run_backtest(_RULE_SPEC_WITHOUT_CORRELATION, store, window_days=7)
    assert result.unique_assets == 2
    assert result.unique_users == 2


def test_max_alerts_per_hour_is_the_busiest_hour_not_the_average():
    store = FakeEventStore(events=[
        _event("5710", "a1", "2026-08-11T10:00:00Z"),
        _event("5710", "a1", "2026-08-11T10:05:00Z"),
        _event("5710", "a1", "2026-08-11T10:10:00Z"),
        _event("5710", "a1", "2026-08-12T03:00:00Z"),  # otro día, otra hora -- 1 sola
    ])
    result = run_backtest(_RULE_SPEC_WITHOUT_CORRELATION, store, window_days=7)
    assert result.max_alerts_per_hour == 3


def test_empty_store_produces_zero_everything():
    store = FakeEventStore(events=[])
    result = run_backtest(_RULE_SPEC_WITH_CORRELATION, store, window_days=7)
    assert result.events_matched == 0
    assert result.estimated_alerts == 0
    assert result.max_alerts_per_hour == 0
    assert result.alerts_per_day == 0.0
