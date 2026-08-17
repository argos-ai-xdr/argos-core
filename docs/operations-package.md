# Paquete Operación XDR (ARG-028)

ARG-028 (S8, propuesta v0.6.25.4 §16.7) define el paquete **"Operación
XDR: Ingesta, correlación, CTI MISP, triaje, dashboards mínimos, salud,
colas y retención"**, validado por "Investigar caso sin ayuda crítica".
Este paquete tiene un perfil MUCHO más mixto que Cyber-range o HITL/SOAR
(`argos-cyber-tools/docs/cyber-range-package.md`,
`argos-smartops/docs/operator-package.md`): varias piezas son interfaz
documentada sin implementación real, no solo "sin cluster real donde
correr". Se listan una por una, sin difuminar la diferencia.

## Reales y probados

* **Ingesta**: `services/asset_reconciler` (fusiona NetBox/CMAM/Kubernetes
  Audit en un `AssetSnapshot`, reporta CONFLICTO explícito si dos fuentes
  discrepan sobre el mismo campo, nunca deja que una sobrescriba a la
  otra en silencio), `services/vulnerability_adapter` (normaliza
  Trivy/OpenVAS a `VulnerabilityFinding`, dedupe real por
  `(asset_id, cve_id, package)`), `services/normalizer` (único punto de
  entrada a `SecurityEvent`, dedupe por `(source, native_ref)`, rechaza
  explícitamente lo que no valida contra schema).
* **Correlación**: `services/correlator.group_by_asset_and_window` —
  regla determinista y explicable (no ML): agrupa por `asset_id` dentro
  de una ventana deslizante, abre grupo nuevo cuando el hueco temporal
  supera la ventana. Produce `Incident` real con `member_event_ids` y
  `timeline` (hecho) separado de `attack_techniques`/`confidence`
  (inferencia).
* **Triaje**: no es un servicio propio — es la severidad que
  `correlator` deriva de los eventos miembro al construir el `Incident`
  (`severity derivada de los eventos`, ver su docstring). La CONSISTENCIA
  de esa severidad (nunca por debajo de la máxima de sus eventos) se
  verifica de forma independiente en
  `argos-validation/evaluators/triage` (AC07).
* **Retención — el schema y el cómputo, no el almacenamiento**:
  `services/evidence_writer.RetentionPolicy` (`policy` + `expires_at`
  opcional) es un campo real y validado de cada `EvidenceManifest`
  producido; el hash `sha256` se calcula de verdad sobre el contenido, no
  un placeholder. Lo que NO existe: la escritura física a Ceph RGW (el
  propio módulo lo documenta: "no implementa todavía la subida real...
  interfaz pendiente ARG-026") ni, por tanto, la aplicación real de esa
  política de retención sobre un objeto almacenado.

## Interfaz documentada, sin implementación real

* **CTI MISP**: `connectors/misp.MISPSource` es un `Protocol`;
  `NotConfiguredMISPSource` (la única implementación) lanza
  `NotImplementedError` en sus dos métodos (`fetch_iocs`,
  `fetch_attack_techniques`), citando ARG-016 explícitamente en el
  mensaje. `argos-contracts-scenarios/snapshots/cti/` solo tiene un
  `manifest-template.yaml` — ningún snapshot MISP real todavía. Por la
  misma razón, `correlator` **nunca calcula `attack_techniques`**: su
  propio docstring lo explica — mapear un evento a una técnica ATT&CK
  real exige las reglas de `argos-contracts-scenarios/mappings/attack/`,
  que hoy solo tiene un `README.md` (sin reglas), y "aceptar
  `attack_techniques` como parámetro opcional del llamador es honesto;
  inventar una técnica plausible no lo sería" (AC08: grounding CTI,
  inventados = 0).
* **Colas**: `libs/argos_events.EventBus` es un `Protocol`;
  `InMemoryEventBus` (síncrono, sin wildcards de NATS `*`/`>`, sin
  persistencia) es la única implementación real hoy. El cliente NATS
  JetStream real (TLS, subjects allowlist, durable consumers, DLQ —
  ADR-002) está pendiente de ARG-015 y de que
  `argos-platform/platform/nats/` se despliegue (sigue `enabled: false`
  en `helm/argos-services/values.yaml`, ver
  `argos-control/releases/0.1.0-dev/as-built.md`).

## No implementado, ni siquiera como interfaz

* **Dashboards mínimos**: no existen. `argos-smartops` tiene una vista
  operativa de incidentes/aprobaciones (cola, detalle — ver
  `argos-smartops/docs/operator-package.md`), pero eso es una interfaz de
  trabajo del operador, no un dashboard de salud/colas/retención del
  propio sistema XDR.
* **Salud**: no existe ningún endpoint `/health`/`/healthz` ni
  equivalente en `argos-core` ni en `argos-smartops` (verificado en
  ambos repos). No hay forma programática hoy de preguntarle al sistema
  "¿estás bien?".

## Lectura honesta del criterio de validación ("Investigar caso sin ayuda crítica")

Un analista SÍ puede seguir el rastro completo de un caso hoy — desde
`SecurityEvent` normalizado, pasando por `Incident` correlacionado con
severidad derivada, hasta la vista de `argos-smartops` — **sin** ayuda
crítica de un desarrollador para ENTENDER el flujo (está probado y
documentado). Lo que NO puede hacer sin ayuda crítica: enriquecer ese
caso con contexto CTI real (MISP no está conectado), confiar en que la
telemetría fluye por un bus productivo (es memoria de un proceso, no
JetStream), o consultar si el propio sistema está sano (no hay endpoint
de salud). El paquete queda `NOT EVALUATED` de forma honesta — no porque
falte documentación, sino porque estas piezas concretas no están
construidas todavía.
