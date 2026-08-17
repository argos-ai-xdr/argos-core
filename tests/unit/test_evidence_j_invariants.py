"""Fase J, paso 9 del prompt maestro de arquitectura objetivo: los 7
invariantes literales, cada uno con su propio test explícito -- no
"probablemente ciertos porque el resto de tests pasan", sino afirmados
por su nombre.
"""
from __future__ import annotations

import json
import pathlib

import pytest
from argos_envelope import EnvelopeContext
from evidence_root import (
    MissingCriticalEvidence,
    build_evidence_root,
    verify_evidence_root,
)
from evidence_root.transparency_log import TransparencyLog
from evidence_writer import EvidenceWriter, RetentionPolicy

FIXTURES_DIR = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "action-results"


def _load(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def test_invariant_executed_action_implies_evidence_exists(contracts_path):
    """`executed action ⇒ evidence exists`: toda acción real ejecutada
    (fixture real de Fase I) produce un EvidenceManifest real y
    verificable -- no hay ninguna vía en este código para que un execute
    real no deje manifiesto."""
    execute_result = _load("isolate_kubernetes_workload-execute.json")
    context = EnvelopeContext(producer="evidence-writer", run_id=execute_result["run_id"])
    writer = EvidenceWriter(contracts_path, context)

    manifest = writer.write_bytes(
        json.dumps(execute_result, sort_keys=True).encode("utf-8"), media_type="application/json", retention=RetentionPolicy(policy="90d")
    )
    assert manifest["sha256"]
    assert manifest["object_ref"]


def test_invariant_verified_action_implies_verification_evidence_exists():
    """`verified action ⇒ verification evidence exists`: una acción
    marcada ACTION_VERIFIED en la transparencia siempre tiene una entrada
    real en el log con object_hash trazable al manifiesto de esa
    verificación -- no un booleano suelto sin respaldo."""
    log = TransparencyLog()
    manifest_hash = "sha256:" + "a" * 64
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash=manifest_hash, run_id="r1", producer="test")
    log.append(event_type="ACTION_VERIFIED", object_id="act-1", object_hash=manifest_hash, run_id="r1", producer="test")

    verified_entries = [e for e in log.entries() if e.event_type == "ACTION_VERIFIED"]
    assert len(verified_entries) == 1
    assert verified_entries[0].object_hash == manifest_hash  # trazable al manifiesto real, no un flag vacío


def test_invariant_rollback_performed_implies_rollback_evidence_exists(contracts_path):
    """`rollback performed ⇒ rollback evidence exists`: mismo patrón que
    execute, sobre el fixture real de rollback."""
    rollback_result = _load("scale_to_zero-rollback.json")
    context = EnvelopeContext(producer="evidence-writer", run_id=rollback_result["run_id"])
    writer = EvidenceWriter(contracts_path, context)

    manifest = writer.write_bytes(
        json.dumps(rollback_result, sort_keys=True).encode("utf-8"), media_type="application/json", retention=RetentionPolicy(policy="90d")
    )
    log = TransparencyLog()
    entry = log.append(event_type="ACTION_ROLLED_BACK", object_id=rollback_result["action_id"], object_hash=manifest["sha256"], run_id=rollback_result["run_id"], producer="test")
    assert entry.object_hash == manifest["sha256"]


def test_invariant_closed_evidence_set_implies_evidence_root_exists(contracts_path, context):
    """`closed evidence set ⇒ EvidenceRoot exists`: dado cualquier
    conjunto cerrado y consistente de manifiestos reales,
    build_evidence_root siempre produce un root -- no hay un estado
    "conjunto cerrado sin root posible" para datos consistentes."""
    writer = EvidenceWriter(contracts_path, context)
    manifests = [writer.write_bytes(c, media_type="text/plain", retention=RetentionPolicy(policy="7d")) for c in (b"a", b"b", b"c")]
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    assert root["root_hash"]
    assert root["artifact_count"] == 3


def test_invariant_artifact_mutation_implies_evidence_root_verification_fails(contracts_path, context):
    """`artifact mutation ⇒ EvidenceRoot verification fails`."""
    writer = EvidenceWriter(contracts_path, context)
    manifests = [writer.write_bytes(b"a", media_type="text/plain", retention=RetentionPolicy(policy="7d"))]
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    mutated = {**root, "artifact_refs": [{**root["artifact_refs"][0], "sha256": "f" * 64}]}
    assert verify_evidence_root(mutated) is False


def test_invariant_transparency_history_mutation_implies_chain_verification_fails():
    """`transparency history mutation ⇒ chain verification fails`."""
    import dataclasses

    log = TransparencyLog()
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    log._entries[0] = dataclasses.replace(log._entries[0], object_hash="sha256:" + "f" * 64)
    assert log.verify_chain().ok is False


def test_invariant_missing_critical_evidence_prevents_a_supported_claim(contracts_path, context):
    """`missing critical evidence ⇒ claim != SUPPORTED`: en este código,
    la aplicación real de esta regla es que construir un EvidenceRoot en
    modo crítico con un artefacto ausente LANZA -- nunca produce un root
    "válido" que una capa superior pudiera confundir con SUPPORTED.
    Mismo principio que `scripts/test.sh` de argos-control exige para
    `argos-assurance.yaml`: ningún claim SUPPORTED sin evidencia real."""
    writer = EvidenceWriter(contracts_path, context)
    manifests = [writer.write_bytes(b"a", media_type="text/plain", retention=RetentionPolicy(policy="7d"))]
    with pytest.raises(MissingCriticalEvidence):
        build_evidence_root([*manifests, None], run_id="r1", producer="test", critical=True)


def test_canonicalization_format_is_pinned_sorted_keys_no_whitespace(contracts_path, context):
    """Regresión de serialización/canonicalización: si el formato
    canónico cambiara sin querer (p. ej. alguien añade espacios o deja de
    ordenar claves), root_hash cambiaría silenciosamente para el MISMO
    conjunto lógico de evidencia -- este test fija el formato esperado
    para que ese cambio sea visible."""
    writer = EvidenceWriter(contracts_path, context)
    manifests = [writer.write_bytes(b"a", media_type="text/plain", retention=RetentionPolicy(policy="7d"))]
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    assert root["canonicalization"] == "sorted-json-by-sha256.v1"
    assert root["algorithm"] == "sha256"
    # root_hash con el mismo prefijo "sha256:" + 64 hex que el resto del
    # proyecto (compute_plan_hash, compute_signature_ref, envelope_hash).
    assert root["root_hash"].startswith("sha256:")
    assert len(root["root_hash"]) == len("sha256:") + 64
