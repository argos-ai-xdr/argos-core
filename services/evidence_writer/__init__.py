"""evidence-writer: única escritura permitida al evidence store (ADR-006,
ADR-016). Construye EvidenceManifest real, hashea el contenido real del
artefacto (no un placeholder) y valida contra el schema antes de devolverlo.

No implementa todavía la subida real a Ceph RGW (argos-platform/platform/
ceph-rgw/) — object_ref se construye con el esquema de URI documentado allí
pero la escritura física es interfaz pendiente (ARG-026).
"""
from __future__ import annotations

import dataclasses
import hashlib
import pathlib

from argos_envelope import EnvelopeContext, build_envelope, new_id_prefixed, utc_now_iso
from argos_testing import build_registry, validate_payload


class InvalidManifest(Exception):
    def __init__(self, errors: list[str]):
        super().__init__(f"EvidenceManifest inválido: {errors}")
        self.errors = errors


@dataclasses.dataclass(frozen=True)
class RetentionPolicy:
    policy: str
    expires_at: str | None = None


class EvidenceWriter:
    def __init__(self, contracts_path: pathlib.Path, context: EnvelopeContext, *, bucket: str = "argos-evidence-artifacts"):
        self._contracts_path = contracts_path
        self._registry = build_registry(contracts_path)
        self._context = context
        self._bucket = bucket

    def write_bytes(
        self,
        content: bytes,
        *,
        media_type: str,
        retention: RetentionPolicy,
        key_hint: str = "artifact",
    ) -> dict:
        """Hashea `content` de verdad (no un valor fijo) y produce un
        EvidenceManifest validado. `content` es lo que ya se escribió/se va
        a escribir en Ceph RGW; este método no hace I/O de red."""
        sha256 = hashlib.sha256(content).hexdigest()
        artifact_id = new_id_prefixed("art")
        object_ref = f"ceph://{self._bucket}/{self._context.run_id}/{key_hint}-{sha256[:12]}"

        payload = {
            "artifact_id": artifact_id,
            "media_type": media_type,
            "object_ref": object_ref,
            "sha256": sha256,
            "created_at": utc_now_iso(),
            "retention": {"policy": retention.policy, **({"expires_at": retention.expires_at} if retention.expires_at else {})},
        }
        envelope = build_envelope(self._context, payload, message_id=artifact_id)
        full_payload = {**envelope, **payload}

        errors = validate_payload(self._contracts_path, self._registry, "evidence-manifest", full_payload)
        if errors:
            raise InvalidManifest(errors)
        return full_payload
