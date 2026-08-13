# Contribuir a argos-core

1. Toda historia debe existir como issue `ARG-###` (ver `argos-control/project/backlog/backlog.yaml`). Primeras historias: ARG-007 (adapter inventario), ARG-008 (ingesta vulnerabilidades), ARG-009 (priorización), ARG-015 (ingesta telemetría), ARG-016 (correlación), ARG-017 (triaje/Incident v1), ARG-019 (Recommendation v1).
2. Rama de trabajo: `feat/ARG-###-descripcion-corta`, `fix/...`.
3. Pull request obligatorio contra `main`. Sin push directo, force-push ni borrado de `main`.
4. Toda salida de un servicio valida contra el schema correspondiente de `argos-contracts-scenarios` — un test de contrato roto bloquea el PR.
5. `recommendation` nunca obtiene credenciales de ejecución ni llama directamente a un ejecutor: solo produce `Recommendation`. Cualquier cambio que lo acerque a ejecución directa requiere un ADR nuevo (contradice ADR-005/ADR-011).
6. `correlator` no puede convertir una inferencia en hecho: todo campo derivado declara su origen.
7. `evidence-writer` es la única escritura permitida al evidence store; ningún otro servicio escribe evidencia directamente.
8. `make validate` y `make test` deben pasar antes de abrir el PR.
