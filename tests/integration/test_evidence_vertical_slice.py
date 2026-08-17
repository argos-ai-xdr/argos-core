"""Fase J, paso 6 del prompt maestro de arquitectura objetivo: vertical
slice real sobre las 3 acciones `execute` reales de Fase I
(`isolate_kubernetes_workload`, `scale_to_zero`, `increase_monitoring`).

Los fixtures de `tests/fixtures/action-results/*.json` NO están escritos
a mano: son el resultado LITERAL de invocar el código real de
`argos-cyber-tools` (`executors/*.py` + `rollback/strategies.py`) —
mismo criterio ya usado para el sample-run de ARGOS-CYB-01 y para la
fixture de SafetyEnvelope. Regenerarlos: ver el script referenciado en
`tests/fixtures/action-results/README.md`.

request → execute → verify → rollback → EvidenceManifest → EvidenceRoot
→ Transparency entry, para las 3 acciones a la vez.
"""
from __future__ import annotations

import json
import pathlib

from argos_envelope import EnvelopeContext
from evidence_root import build_evidence_root, verify_evidence_root
from evidence_root.replay import replay_and_verify
from evidence_root.transparency_log import TransparencyLog
from evidence_writer import EvidenceWriter, RetentionPolicy

FIXTURES_DIR = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "action-results"
TOOLS = ("isolate_kubernetes_workload", "scale_to_zero", "increase_monitoring")

REQUIRED_EVENTS = frozenset({"ACTION_EXECUTED", "ACTION_VERIFIED", "ACTION_ROLLED_BACK", "EVIDENCE_ROOT_CREATED"})


def _load(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def test_all_three_real_actions_produce_a_verified_replay(contracts_path):
    execute_results = {tool: _load(f"{tool}-execute.json") for tool in TOOLS}
    rollback_results = {tool: _load(f"{tool}-rollback.json") for tool in TOOLS}

    run_ids = {r["run_id"] for r in execute_results.values()} | {r["run_id"] for r in rollback_results.values()}
    assert len(run_ids) == 1, "los 3 fixtures deben compartir run_id (mismo run reconstruible)"
    run_id = run_ids.pop()

    context = EnvelopeContext(producer="evidence-writer", run_id=run_id)
    writer = EvidenceWriter(contracts_path, context)
    log = TransparencyLog()
    manifests: list[dict] = []

    for tool in TOOLS:
        execute_result = execute_results[tool]
        rollback_result = rollback_results[tool]

        # execute -- ya ocurrió de verdad (fixture = salida real del executor).
        execute_bytes = json.dumps(execute_result, sort_keys=True, ensure_ascii=False).encode("utf-8")
        execute_manifest = writer.write_bytes(execute_bytes, media_type="application/json", retention=RetentionPolicy(policy="90d"))
        manifests.append(execute_manifest)
        log.append(
            event_type="ACTION_EXECUTED",
            object_id=execute_result["action_id"],
            object_hash=execute_manifest["sha256"],
            run_id=run_id,
            producer=tool,
        )

        # verify -- el propio ActionResult real ya trae verification.passed
        # (recomputado por rollback/verification.py en Fase I, no un campo
        # que este test invente).
        assert execute_result["verification"]["passed"] is True, f"{tool}: el fixture real no reporta verificación exitosa"
        log.append(
            event_type="ACTION_VERIFIED",
            object_id=execute_result["action_id"],
            object_hash=execute_manifest["sha256"],
            run_id=run_id,
            producer=tool,
        )

        # rollback -- también ocurrió de verdad.
        rollback_bytes = json.dumps(rollback_result, sort_keys=True, ensure_ascii=False).encode("utf-8")
        rollback_manifest = writer.write_bytes(rollback_bytes, media_type="application/json", retention=RetentionPolicy(policy="90d"))
        manifests.append(rollback_manifest)
        assert rollback_result["verification"]["passed"] is True, f"{tool}: el rollback real no reporta verificación exitosa"
        log.append(
            event_type="ACTION_ROLLED_BACK",
            object_id=rollback_result["action_id"],
            object_hash=rollback_manifest["sha256"],
            run_id=run_id,
            producer=tool,
        )

    # EvidenceRoot sobre los 6 manifiestos (3 execute + 3 rollback).
    root = build_evidence_root(manifests, run_id=run_id, producer="evidence-root-aggregator")
    assert root["artifact_count"] == 6
    assert verify_evidence_root(root)
    log.append(event_type="EVIDENCE_ROOT_CREATED", object_id=root["root_id"], object_hash=root["root_hash"], run_id=run_id, producer="evidence-root-aggregator")

    receipt = log.issue_receipt(root["root_id"])
    assert receipt.event_type == "EVIDENCE_ROOT_CREATED"

    result = replay_and_verify(run_id=run_id, manifests=manifests, evidence_root=root, log=log, required_event_types=REQUIRED_EVENTS)
    assert result.state == "VERIFIED", result.detail
    assert result.ok


def test_tampering_any_one_action_result_after_the_fact_breaks_the_replay(contracts_path):
    """Regresión objetivo: si alguien reescribe el ActionResult real de
    UNA sola de las 3 acciones después de sellado, la reconstrucción
    completa debe dejar de verificar -- no solo la acción afectada."""
    execute_results = {tool: _load(f"{tool}-execute.json") for tool in TOOLS}
    run_id = execute_results["isolate_kubernetes_workload"]["run_id"]
    context = EnvelopeContext(producer="evidence-writer", run_id=run_id)
    writer = EvidenceWriter(contracts_path, context)

    manifests = []
    real_bytes_by_id = {}
    for tool in TOOLS:
        content = json.dumps(execute_results[tool], sort_keys=True, ensure_ascii=False).encode("utf-8")
        manifest = writer.write_bytes(content, media_type="application/json", retention=RetentionPolicy(policy="90d"))
        manifests.append(manifest)
        real_bytes_by_id[manifest["artifact_id"]] = content

    root = build_evidence_root(manifests, run_id=run_id, producer="evidence-root-aggregator")
    log = TransparencyLog()
    log.append(event_type="EVIDENCE_ROOT_CREATED", object_id=root["root_id"], object_hash=root["root_hash"], run_id=run_id, producer="test")

    # "Alguien" reescribe uno de los ActionResult reales tras el hecho.
    tampered_id = manifests[0]["artifact_id"]
    real_bytes_by_id[tampered_id] = b'{"status": "tampered"}'

    result = replay_and_verify(run_id=run_id, manifests=manifests, evidence_root=root, log=log, artifact_bytes_by_id=real_bytes_by_id)
    assert result.state == "HASH_MISMATCH"
