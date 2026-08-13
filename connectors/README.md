# connectors/

Cada conector es una interfaz Python real (`Protocol`) más una clase `NotConfigured*` que lanza `NotImplementedError` con un mensaje que dice exactamente qué falta y en qué historia `ARG-###` se resuelve — en vez de un README aparte por conector, esa documentación vive en el docstring del propio módulo (léelo antes de implementar uno).

| Conector | Alimenta a | Estado |
| --- | --- | --- |
| [`netbox/`](netbox/) | `asset_reconciler` | Interfaz, pendiente ARG-007 |
| [`cmam/`](cmam/) | `asset_reconciler` | Interfaz, pendiente ARG-007/DEP-03 (opcional para MVP) |
| [`kubernetes_audit/`](kubernetes_audit/) | `asset_reconciler` + `normalizer` | Interfaz, pendiente ARG-007/ARG-015 |
| [`trivy/`](trivy/) | `vulnerability_adapter` | Interfaz, pendiente ARG-008 |
| [`openvas/`](openvas/) | `vulnerability_adapter` | Interfaz, pendiente ARG-008 |
| [`vmt/`](vmt/) | `vulnerability_adapter` | Interfaz, pendiente ARG-008/DEP-03 (opcional para MVP) |
| [`wazuh/`](wazuh/) | `normalizer` | Interfaz, pendiente ARG-015 |
| [`falco/`](falco/) | `normalizer` | Interfaz, pendiente ARG-015/DEP-05 |
| [`hubble/`](hubble/) | `normalizer` | Interfaz, pendiente ARG-015/DEP-05 |
| [`misp/`](misp/) | `correlator` (attack_techniques) | Interfaz, pendiente ARG-016 |

Ninguno tiene implementación real todavía — es deliberado. La toolchain P0 (ADR-010) fija qué herramientas son estas diez; cuándo se implementa cada una la fija el backlog (`argos-control/project/backlog/backlog.yaml`), no este repositorio.
