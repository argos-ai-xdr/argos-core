# policy-adapter

Cliente hacia el PDP real (OPA, `argos-cyber-tools/policies/opa/`, ADR-005) — `OPAClient` es interfaz documentada, no implementada (ARG-020). `InMemoryPolicyDecisionPoint` reimplementa en Python la misma regla que `argos-contracts-scenarios/scenarios/ARGOS-CYB-01/policies/isolate-kubernetes-workload.rego` (F07): `ALLOW_DRY_RUN` en dry-run dentro de la allowlist, `APPROVAL_REQUIRED` en execute dentro de la allowlist, `DENY` fuera de ella — para poder probar el resto de `argos-core` sin un OPA real desplegado.

`argos-core` no es dueño de la política de producción; si esta regla y el `.rego` divergen, el `.rego` de `argos-contracts-scenarios` manda.
