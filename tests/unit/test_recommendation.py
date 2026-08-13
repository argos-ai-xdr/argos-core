from __future__ import annotations

import pytest
from recommendation import DeterministicFallbackEngine, LangGraphEngine


def _incident(severity):
    return {"incident_id": "inc-x", "severity": severity, "evidence_refs": ["env-e1"]}


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
def test_fallback_produces_valid_recommendation_for_every_severity(contracts_path, context, severity):
    engine = DeterministicFallbackEngine(contracts_path, context)
    reco = engine.generate(_incident(severity))
    assert reco["alternatives"]
    assert reco["selected_action"] == reco["alternatives"][0]["action"]


def test_unknown_severity_falls_back_to_low(contracts_path, context):
    engine = DeterministicFallbackEngine(contracts_path, context)
    reco = engine.generate(_incident("nonexistent"))
    assert reco["selected_action"] == "log_only"


def test_langgraph_engine_not_implemented():
    with pytest.raises(NotImplementedError):
        LangGraphEngine().generate(_incident("high"))


def test_fallback_never_imports_execution_client():
    """Chequeo estático real sobre las sentencias import (ast, no substring
    ingenuo): 'kubernetes' aparece legítimamente en el nombre de la acción
    'isolate_kubernetes_workload' del runbook, así que buscar la palabra en
    todo el texto fuente da un falso positivo — hay que mirar solo los
    imports reales (ADR-005/ADR-011: recommendation nunca ejecuta)."""
    import ast
    import inspect

    import recommendation

    tree = ast.parse(inspect.getsource(recommendation))
    imported_modules = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    forbidden = {"subprocess", "socket", "requests", "kubernetes", "cyber_tools"}
    assert not (imported_modules & forbidden), imported_modules & forbidden
