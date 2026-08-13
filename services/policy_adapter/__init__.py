"""policy-adapter: cliente hacia el PDP (OPA, ADR-005). La decisión real vive
en argos-cyber-tools/policies/opa/ (no en este repositorio — argos-core no
es dueño de la política). InMemoryPolicyDecisionPoint reimplementa en Python
la MISMA regla que argos-contracts-scenarios/scenarios/ARGOS-CYB-01/policies/
isolate-kubernetes-workload.rego (F07), para poder probar el resto de
argos-core sin un servidor OPA real desplegado.

Regla (F07): ALLOW_DRY_RUN para dry-run dentro de la allowlist;
APPROVAL_REQUIRED para execute dentro de la allowlist; DENY fuera de ella.
"""
from __future__ import annotations

from typing import Protocol

from argos_envelope import EnvelopeContext, build_envelope, new_id_prefixed
from argos_testing import build_registry, validate_payload


class InvalidPolicyDecision(Exception):
    def __init__(self, errors: list[str]):
        super().__init__(f"PolicyDecision inválida: {errors}")
        self.errors = errors


class PolicyDecisionPoint(Protocol):
    def evaluate(self, *, subject: str, tool: str, action: str, target: str) -> dict: ...


class OPAClient:
    """Cliente HTTP real hacia argos-cyber-tools/mcp-gateway — no
    implementado en este bootstrap (ARG-020: OPA policy gate, approval API).
    """

    def __init__(self, base_url: str):
        self._base_url = base_url

    def evaluate(self, *, subject: str, tool: str, action: str, target: str) -> dict:
        raise NotImplementedError(
            f"OPAClient contra {self._base_url} no implementado todavía "
            "(ARG-020); usar InMemoryPolicyDecisionPoint para desarrollo local."
        )


class InMemoryPolicyDecisionPoint:
    def __init__(
        self,
        contracts_path,
        context: EnvelopeContext,
        *,
        target_allowlist: set[str],
        policy_version: str = "0.1.0-local",
    ):
        self._contracts_path = contracts_path
        self._registry = build_registry(contracts_path)
        self._context = context
        self._target_allowlist = target_allowlist
        self._policy_version = policy_version

    def evaluate(self, *, subject: str, tool: str, action: str, target: str) -> dict:
        if target not in self._target_allowlist:
            result = "DENY"
            reason = f"target '{target}' fuera de la allowlist"
        elif action == "execute":
            result = "APPROVAL_REQUIRED"
            reason = "execute requiere aprobación humana vinculada al action_id (ADR-011)"
        elif action == "dry-run":
            result = "ALLOW_DRY_RUN"
            reason = "dry-run permitido dentro de la allowlist"
        else:
            result = "DENY"
            reason = f"acción desconocida '{action}'"

        decision_id = new_id_prefixed("pol")
        payload = {
            "decision_id": decision_id,
            "policy_version": self._policy_version,
            "subject": subject,
            "tool": tool,
            "action": action,
            "target": target,
            "result": result,
            "reason": reason,
        }
        envelope = build_envelope(self._context, payload, message_id=decision_id)
        full_payload = {**envelope, **payload}

        errors = validate_payload(self._contracts_path, self._registry, "policy-decision", full_payload)
        if errors:
            raise InvalidPolicyDecision(errors)
        return full_payload
