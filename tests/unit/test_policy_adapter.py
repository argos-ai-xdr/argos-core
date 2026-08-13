from __future__ import annotations

import pytest
from policy_adapter import InMemoryPolicyDecisionPoint, OPAClient


def _pdp(context, contracts_path):
    return InMemoryPolicyDecisionPoint(contracts_path, context, target_allowlist={"deployment/gseg-simulado"})


def test_execute_in_allowlist_requires_approval(contracts_path, context):
    decision = _pdp(context, contracts_path).evaluate(
        subject="s", tool="isolate_kubernetes_workload", action="execute", target="deployment/gseg-simulado"
    )
    assert decision["result"] == "APPROVAL_REQUIRED"


def test_dry_run_in_allowlist_is_allowed(contracts_path, context):
    decision = _pdp(context, contracts_path).evaluate(
        subject="s", tool="isolate_kubernetes_workload", action="dry-run", target="deployment/gseg-simulado"
    )
    assert decision["result"] == "ALLOW_DRY_RUN"


def test_target_outside_allowlist_is_denied_regardless_of_action(contracts_path, context):
    for action in ("execute", "dry-run"):
        decision = _pdp(context, contracts_path).evaluate(
            subject="s", tool="x", action=action, target="namespace/prod"
        )
        assert decision["result"] == "DENY"


def test_unknown_action_is_denied(contracts_path, context):
    decision = _pdp(context, contracts_path).evaluate(
        subject="s", tool="x", action="delete-everything", target="deployment/gseg-simulado"
    )
    assert decision["result"] == "DENY"


def test_opa_client_is_not_implemented():
    with pytest.raises(NotImplementedError):
        OPAClient("http://opa.local").evaluate(subject="s", tool="t", action="execute", target="x")
