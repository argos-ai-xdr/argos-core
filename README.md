# argos-core

Lógica funcional principal del AI-assisted XDR: normalización, correlación, priorización de riesgo, recomendación y escritura de evidencia. No incluye la ejecución directa de acciones críticas — eso vive en `argos-cyber-tools`.

Parte de la organización [`argos-ai-xdr`](https://github.com/argos-ai-xdr). Arquitectura autoritativa y ADR en [`argos-control`](https://github.com/argos-ai-xdr/argos-control). Contratos y fixtures en [`argos-contracts-scenarios`](https://github.com/argos-ai-xdr/argos-contracts-scenarios).

Stack: Python, FastAPI, Pydantic, NATS, OpenTelemetry (ver `argos-control` — "para reducir complejidad durante el MVP" solo se introduce otro lenguaje si una medición lo justifica).

## Contenido

| Carpeta | Contenido |
| --- | --- |
| `services/` | Los nueve servicios (uno por responsabilidad; ver tabla abajo) |
| `libs/` | Librerías internas versionadas compartidas entre servicios |
| `connectors/` | Adaptadores hacia sistemas externos (NetBox, CMAM, Trivy, Wazuh, MISP, ...) |
| `models/` | Prompts, salida estructurada, fallback determinista, config de evaluación |
| `deploy/` | Helm/Kustomize por servicio, promovido vía `argos-platform` |
| `tests/` | `unit/`, `integration/`, `contract/`, `replay/`, `security/` |

## Servicios

| Servicio | Responsabilidad | Estado en este bootstrap |
| --- | --- | --- |
| `normalizer` | Valida `SecurityEvent`, asigna `event_id`/`run_id`, deduplica, normaliza severidad | Lógica real |
| `asset-reconciler` | Ingesta CMAM/NetBox/K8s, reconcilia activos, detecta drift | Lógica real |
| `vulnerability-adapter` | Normaliza hallazgos Trivy/OpenVAS a `VulnerabilityFinding` | Lógica real |
| `risk-engine` | Ranking explicable (exposición, criticidad, KEV, EPSS) | Lógica real |
| `correlator` | Construye `Incident`, separa hecho de inferencia | Lógica real |
| `recommendation` | Fallback determinista real; LangGraph/vLLM documentado, no implementado (ADR-008) | Parcial |
| `policy-adapter` | Cliente hacia OPA (`argos-cyber-tools`) | Interfaz + fake en memoria |
| `evidence-writer` | Construye `EvidenceManifest`, hashea artefactos | Lógica real |
| `soc-adapter` | Filtra por TLP, construye `SOCHandover` | Lógica real |

## Nota de nombres de paquete

Igual que en `argos-validation`: Python no permite guiones en nombres de paquete. `asset-reconciler`, `vulnerability-adapter`, `policy-adapter`, `evidence-writer`, `soc-adapter` y `kubernetes-audit` viven en disco con guion bajo (`asset_reconciler/`, etc.) e importan como `import asset_reconciler`. El nombre del **servicio** (con guion) es el que aparece en ADR, backlog y `repository.yaml`; el nombre del **paquete** (con guion bajo) es solo la realidad de Python.

## Reglas comunes de la organización

* Rama principal: `main`. Sin rama permanente `develop`.
* Pull request obligatorio; revisión de `CODEOWNERS`; checks de CI obligatorios.
* Prohibido push directo, force-push y borrado de `main`.
* Todas las salidas validan contra los schemas de `argos-contracts-scenarios`.
* El LLM (`recommendation`) no posee credenciales de ejecución; existe fallback determinista.
* Ninguna inferencia se presenta como hecho (`correlator`).
* Trazas y métricas contienen `run_id` (ADR-009); sin chain-of-thought (ADR-016).

Ver `docs/development.md`.
