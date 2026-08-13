# evidence-writer

Única escritura permitida al evidence store (ADR-006/ADR-016). `EvidenceWriter.write_bytes` hashea el contenido real (SHA-256 de los bytes, no un valor fijo) y valida el `EvidenceManifest` resultante contra `argos-contracts-scenarios/schemas/evidence-manifest/v1.schema.json` antes de devolverlo.

* **Pendiente**: subida física a Ceph RGW (`argos-platform/platform/ceph-rgw/`) — hoy `object_ref` se construye con el esquema de URI documentado allí, pero no hay I/O de red (ARG-026).
* **Regla**: ningún otro servicio de este repositorio debe construir un `object_ref` ni escribir en el bucket de evidencia directamente — importan `argos_evidence` (cliente) o llaman a este servicio.
