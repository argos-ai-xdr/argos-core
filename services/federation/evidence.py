"""federation.evidence: integra Federation (Fase L) con la
infraestructura de evidencia ya real de Fase J -- mismo patrón que
`mission_context.evidence` (Fase K).

**No crea un mecanismo de evidencia paralelo.** Reutiliza
`evidence_writer.EvidenceWriter` y `evidence_root.build_evidence_root`
tal cual -- este módulo solo construye los PAYLOADS (`FederationDecisionRecord`
/ `CrossDomainTransferRecord`) que se hashean y anclan con esos
mecanismos ya probados en Fase J.

**Nota de diseño honesta sobre §24 del prompt:** el prompt original
enumera tipos de evento específicos (`FEDERATED_ARTIFACT_RECEIVED`,
`FEDERATION_ACCEPTED`, `FEDERATION_QUARANTINED`, ...). El propio §24
también exige "usar solo tipos de evento que encajen con las
convenciones actuales" y "ningún mecanismo de evidencia paralelo".
`transparency_log.VALID_EVENT_TYPES` (Fase J) es un frozenset cerrado
que NO incluye ningún evento de federación, y ni siquiera Fase K
(`mission_context.evidence`) añadió eventos de misión propios -- el
patrón ya establecido (ver `tests/integration/
test_k1_mission_verifier_vertical_slice.py`) es anclar cualquier
`EvidenceRoot` nuevo bajo el evento genérico ya real `EVIDENCE_ROOT_CREATED`,
con `object_id=root["root_id"]`, dejando el tipo de decisión real
(`ACCEPT`/`QUARANTINE`/`REJECT`/`RELEASED`/`DENIED`/...) como CONTENIDO
del record ya hasheado, no como un tipo de evento nuevo en el log. Se
sigue ese mismo patrón aquí en vez de ampliar `VALID_EVENT_TYPES` con
ocho constantes que ningún otro dominio del repositorio usa todavía.
"""
from __future__ import annotations

import dataclasses
import json

from argos_envelope import EnvelopeContext, utc_now_iso
from evidence_root import build_evidence_root
from evidence_writer import EvidenceWriter, RetentionPolicy

from federation.cross_domain_transfer import CrossDomainTransfer
from federation.decision import FederationDecision
from federation.federated_artifact import FederatedArtifact


def build_federation_decision_record(*, decision: FederationDecision, artifact: FederatedArtifact) -> dict:
    """Payload puro, serializable -- ninguna llamada de red ni escritura
    de evidencia aquí (eso lo hace `record_federation_evidence`)."""
    return {
        "record_id": decision.decision_id,
        "record_type": "FederationDecisionRecord",
        "artifact_ref": artifact.artifact_id,
        "artifact_type": artifact.artifact_type,
        "origin_instance": artifact.origin_instance,
        "origin_domain": artifact.origin_domain,
        "content_hash": artifact.content_hash,
        "local_domain": decision.local_domain,
        "decision": decision.decision,
        "reason_codes": list(decision.reason_codes),
        "required_revalidation": list(decision.required_revalidation),
        "semantic_conflict_result": decision.semantic_conflict_result,
        "decision_time": decision.decision_time,
        "created_at": utc_now_iso(),
    }


def build_cross_domain_transfer_record(*, transfer: CrossDomainTransfer) -> dict:
    return {
        "record_id": transfer.transfer_id,
        "record_type": "CrossDomainTransferRecord",
        "source_domain": transfer.source_domain,
        "destination_domain": transfer.destination_domain,
        "artifact_ref": transfer.artifact_ref,
        "original_classification": transfer.original_classification,
        "requested_classification": transfer.requested_classification,
        "released_classification": transfer.released_classification,
        "fields_removed": list(transfer.fields_removed),
        "outcome": transfer.outcome,
        "approver_ref": transfer.approver_ref,
        "original_hash": transfer.original_hash,
        "released_hash": transfer.released_hash,
        "timestamp": transfer.timestamp,
        "created_at": utc_now_iso(),
    }


@dataclasses.dataclass(frozen=True)
class FederationEvidence:
    record: dict
    manifest: dict
    evidence_root: dict


def record_federation_evidence(
    record: dict,
    *,
    contracts_path,
    context: EnvelopeContext,
    run_id: str,
) -> FederationEvidence:
    """Ancla el record con el mecanismo de Fase J tal cual, sin
    duplicarlo -- idéntico a `mission_context.evidence.
    record_mission_decision_evidence`."""
    writer = EvidenceWriter(contracts_path, context)
    content = json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
    manifest = writer.write_bytes(content, media_type="application/json", retention=RetentionPolicy(policy="365d"))
    root = build_evidence_root([manifest], run_id=run_id, producer="federation-decision-record", incident_id=record.get("artifact_ref"))
    return FederationEvidence(record=record, manifest=manifest, evidence_root=root)
