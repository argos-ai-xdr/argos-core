# action-results/

6 `ActionResult` v1 reales (no escritos a mano): salida LITERAL de
invocar el código real de `argos-cyber-tools` — los 3 executores de
Fase I (`isolate_kubernetes_workload`, `scale_to_zero`,
`increase_monitoring`) más sus 3 rollbacks correspondientes. Usados por
`tests/integration/test_evidence_vertical_slice.py` (Fase J).

Regenerar (requiere `argos-cyber-tools` clonado como hermano, con
`pip install -e .`):

```python
from executors.increase_monitoring import IncreaseMonitoringExecutor
from executors.kubernetes import KubernetesExecutor
from executors.scale_to_zero import ScaleToZeroExecutor
from rollback.strategies import rollback_increase_monitoring, rollback_isolation, rollback_scale_to_zero

# ... invocar cada executor con dry_run=False y su rollback correspondiente,
# usando el MISMO run_id en los 6 (aquí: "run-evidence-j-001"),
# volcar cada payload devuelto a su .json con json.dumps(payload, indent=2).
```

No se regeneran automáticamente en CI: son una fotografía congelada de
un run real, igual que `argos-contracts-scenarios/scenarios/ARGOS-CYB-01/
expected/sample-run/`.
