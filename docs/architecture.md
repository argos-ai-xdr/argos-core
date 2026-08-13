# Arquitectura de argos-core

Implementa los planos P2 (XDR/contexto) y P3 (IA/política, parcialmente — `recommendation`) de `argos-control/architecture/logical/planos.md`, más `evidence-writer` en P6.

## Flujo interno (subconjunto del flujo end-to-end de argos-control)

```
connectors/{wazuh,falco,hubble,kubernetes-audit} ──▶ services/normalizer ──▶ NATS (security.event.v1)
connectors/{netbox,cmam,kubernetes-audit}        ──▶ services/asset-reconciler ──▶ AssetSnapshot
connectors/{trivy,openvas,vmt}                   ──▶ services/vulnerability-adapter ──▶ VulnerabilityFinding
(AssetSnapshot + VulnerabilityFinding)            ──▶ services/risk-engine ──▶ ranking explicable
(SecurityEvent + connectors/misp)                 ──▶ services/correlator ──▶ Incident
Incident                                          ──▶ services/recommendation ──▶ Recommendation
Recommendation                                    ──▶ services/policy_adapter ──▶ PolicyDecision (via argos-cyber-tools/OPA)
Todo lo anterior                                  ──▶ services/evidence_writer ──▶ EvidenceManifest
Incident + ActionResult                           ──▶ services/soc_adapter ──▶ SOCHandover
```

## Reglas que no se pueden romper (ver ADR de argos-control)

* `normalizer` es el único punto de entrada a `SecurityEvent`; nada aguas abajo revalida contra el schema.
* `correlator` separa explícitamente hechos (eventos) de inferencias (técnicas ATT&CK, confidence) — un campo derivado siempre declara su origen.
* `recommendation` no tiene credenciales de ejecución (ADR-005/ADR-008/ADR-011); su fallback determinista debe producir una `Recommendation` válida sin LLM.
* `evidence_writer` es la única escritura al evidence store; nadie más escribe evidencia (ADR-006).
* Todas las salidas validan contra `argos-contracts-scenarios/schemas/`.

Ver `argos-control/architecture/data-flows/end-to-end-flow.md` para el flujo completo, incluida la parte que vive en `argos-cyber-tools` y `argos-smartops`.
