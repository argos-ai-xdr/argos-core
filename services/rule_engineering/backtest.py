"""backtest: "¿qué habría pasado si esta regla hubiera estado activa
durante los últimos N días?" (ADR-069 §10) -- calculado contra un
histórico REAL de eventos, nunca estimado a ojo. Sin `argos-platform`
desplegado, `argos-validation`/`argos-core` no tienen acceso a un
OpenSearch real todavía (`BLOCKED_EXTERNAL`) -- `FakeEventStore` es un
histórico en memoria con la MISMA forma de datos que se usaría contra
OpenSearch real, para que `run_backtest` sea la misma función en ambos
casos (mismo patrón que `FakeClusterState` en
`argos-cyber-tools/executors`).

Reutiliza la misma regla de agrupación temporal que
`argos-core/services/correlator.group_by_asset_and_window` (orden +
huecos > ventana abre grupo nuevo) en vez de reinventar otra -- una
`WazuhRuleSpec` con `frequency`/`timeframe_seconds` declara exactamente
lo mismo que `frequency`+`timeframe` en un `<rule>` real de Wazuh.
"""
from __future__ import annotations

import dataclasses
import datetime


@dataclasses.dataclass
class FakeEventStore:
    """Histórico en memoria. Cada evento: {wazuh_rule_id, asset_id,
    source_ip, user, observed_at (ISO8601)} -- mismos campos que
    aportaría un SecurityEvent real ya normalizado."""

    events: list[dict] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class BacktestResult:
    events_matched: int
    estimated_alerts: int
    unique_assets: int
    unique_users: int
    alerts_per_day: float
    max_alerts_per_hour: int


def _parse(observed_at: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(observed_at)


def _correlation_key(event: dict, *, same_source_ip: bool, same_user: bool) -> tuple:
    key: list[object] = [event.get("asset_id", "unknown")]
    if same_source_ip:
        key.append(("source_ip", event.get("source_ip")))
    if same_user:
        key.append(("user", event.get("user")))
    return tuple(key)


def _group_by_key_and_window(events: list[dict], *, key_fn, window: datetime.timedelta) -> list[list[dict]]:
    by_key: dict[tuple, list[dict]] = {}
    for event in events:
        by_key.setdefault(key_fn(event), []).append(event)

    groups: list[list[dict]] = []
    for members in by_key.values():
        members.sort(key=lambda e: _parse(e["observed_at"]))
        current: list[dict] = []
        last_time: datetime.datetime | None = None
        for event in members:
            event_time = _parse(event["observed_at"])
            if last_time is not None and (event_time - last_time) > window:
                groups.append(current)
                current = []
            current.append(event)
            last_time = event_time
        if current:
            groups.append(current)
    return groups


def run_backtest(rule_spec: dict, event_store: FakeEventStore, *, window_days: int) -> BacktestResult:
    matched = [e for e in event_store.events if e.get("wazuh_rule_id") == rule_spec.get("parent_rule_sid")]

    correlation = rule_spec.get("correlation") or {}
    frequency = correlation.get("frequency")
    timeframe_seconds = correlation.get("timeframe_seconds")

    if frequency and timeframe_seconds:
        groups = _group_by_key_and_window(
            matched,
            key_fn=lambda e: _correlation_key(
                e, same_source_ip=bool(correlation.get("same_source_ip")), same_user=bool(correlation.get("same_user"))
            ),
            window=datetime.timedelta(seconds=timeframe_seconds),
        )
        firing_groups = [g for g in groups if len(g) >= frequency]
        estimated_alerts = len(firing_groups)
    else:
        # Sin correlación declarada: cada evento que matchea es una alerta.
        estimated_alerts = len(matched)

    unique_assets = len({e.get("asset_id") for e in matched if e.get("asset_id")})
    unique_users = len({e.get("user") for e in matched if e.get("user")})
    alerts_per_day = estimated_alerts / window_days if window_days else 0.0

    max_alerts_per_hour = 0
    if matched:
        by_hour: dict[str, int] = {}
        for event in matched:
            hour_bucket = _parse(event["observed_at"]).strftime("%Y-%m-%dT%H")
            by_hour[hour_bucket] = by_hour.get(hour_bucket, 0) + 1
        max_alerts_per_hour = max(by_hour.values())

    return BacktestResult(
        events_matched=len(matched),
        estimated_alerts=estimated_alerts,
        unique_assets=unique_assets,
        unique_users=unique_users,
        alerts_per_day=alerts_per_day,
        max_alerts_per_hour=max_alerts_per_hour,
    )
