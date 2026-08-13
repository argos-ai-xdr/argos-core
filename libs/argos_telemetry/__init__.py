"""Propagación de run_id/trace_id (ADR-009: correlación transversal por
run_id/trace_id). No añade la dependencia opentelemetry-sdk todavía — es un
facade mínimo real (contextvars) que cualquier servicio puede usar hoy; el
exporter OTel real hacia argos-platform/observability/otel-collector/ es
interfaz pendiente de ARG-015.

Regla dura (ADR-016): nunca propagar chain-of-thought del modelo por esta
vía. Este módulo no tiene ningún campo para ello a propósito.
"""
from __future__ import annotations

import contextlib
import contextvars
import uuid

_run_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("argos_run_id", default=None)
_trace_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("argos_trace_id", default=None)


def new_id() -> str:
    return uuid.uuid4().hex


def current_run_id() -> str | None:
    return _run_id_var.get()


def current_trace_id() -> str | None:
    return _trace_id_var.get()


@contextlib.contextmanager
def run_context(run_id: str | None = None, trace_id: str | None = None):
    """Fija run_id/trace_id para todo el código ejecutado dentro del bloque
    `with`, incluidas llamadas anidadas — sin pasar el valor a mano por
    cada función."""
    run_token = _run_id_var.set(run_id or new_id())
    trace_token = _trace_id_var.set(trace_id or new_id())
    try:
        yield current_run_id(), current_trace_id()
    finally:
        _run_id_var.reset(run_token)
        _trace_id_var.reset(trace_token)
