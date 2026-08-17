from __future__ import annotations

from evidence_root import build_evidence_root
from evidence_root.replay import replay_and_verify
from evidence_root.transparency_log import TransparencyLog
from evidence_writer import EvidenceWriter, RetentionPolicy


def _manifests(contracts_path, context, contents: list[bytes]) -> list[dict]:
    writer = EvidenceWriter(contracts_path, context)
    return [writer.write_bytes(c, media_type="text/plain", retention=RetentionPolicy(policy="7d")) for c in contents]


def _log_with_root_created(run_id: str, root_hash: str) -> TransparencyLog:
    log = TransparencyLog()
    log.append(event_type="EVIDENCE_ROOT_CREATED", object_id=run_id, object_hash=root_hash, run_id=run_id, producer="test")
    return log


def test_replay_verified_on_a_clean_reconstruction(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a", b"b"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    log = _log_with_root_created("r1", root["root_hash"])

    result = replay_and_verify(run_id="r1", manifests=manifests, evidence_root=root, log=log)
    assert result.state == "VERIFIED"
    assert result.ok


def test_replay_broken_chain_when_transparency_log_was_tampered(contracts_path, context):
    import dataclasses

    manifests = _manifests(contracts_path, context, [b"a"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    log = _log_with_root_created("r1", root["root_hash"])
    log._entries[0] = dataclasses.replace(log._entries[0], object_hash="sha256:" + "f" * 64)

    result = replay_and_verify(run_id="r1", manifests=manifests, evidence_root=root, log=log)
    assert result.state == "BROKEN_CHAIN"
    assert not result.ok


def test_replay_hash_mismatch_when_evidence_root_is_self_inconsistent(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    tampered_root = {**root, "root_hash": "sha256:" + "0" * 64}
    log = _log_with_root_created("r1", root["root_hash"])

    result = replay_and_verify(run_id="r1", manifests=manifests, evidence_root=tampered_root, log=log)
    assert result.state == "HASH_MISMATCH"


def test_replay_missing_artifact_when_a_manifest_is_not_in_the_root(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a", b"b"])
    root = build_evidence_root(manifests[:1], run_id="r1", producer="test")  # el root solo cubre el primero
    log = _log_with_root_created("r1", root["root_hash"])

    result = replay_and_verify(run_id="r1", manifests=manifests, evidence_root=root, log=log)
    assert result.state == "MISSING_ARTIFACT"


def test_replay_missing_artifact_when_root_references_a_manifest_not_provided(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a", b"b"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    log = _log_with_root_created("r1", root["root_hash"])

    result = replay_and_verify(run_id="r1", manifests=manifests[:1], evidence_root=root, log=log)  # falta el 2º manifiesto
    assert result.state == "MISSING_ARTIFACT"


def test_replay_hash_mismatch_when_real_bytes_do_not_match_the_manifest(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    log = _log_with_root_created("r1", root["root_hash"])

    result = replay_and_verify(
        run_id="r1",
        manifests=manifests,
        evidence_root=root,
        log=log,
        artifact_bytes_by_id={manifests[0]["artifact_id"]: b"TAMPERED-CONTENT"},
    )
    assert result.state == "HASH_MISMATCH"


def test_replay_verified_when_real_bytes_match_the_manifest(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    log = _log_with_root_created("r1", root["root_hash"])

    result = replay_and_verify(
        run_id="r1", manifests=manifests, evidence_root=root, log=log, artifact_bytes_by_id={manifests[0]["artifact_id"]: b"a"}
    )
    assert result.state == "VERIFIED"


def test_replay_incomplete_when_required_event_types_are_missing(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    log = TransparencyLog()  # sin ningún evento

    result = replay_and_verify(run_id="r1", manifests=manifests, evidence_root=root, log=log)
    assert result.state == "INCOMPLETE"


def test_replay_incomplete_when_caller_requires_rollback_evidence_that_is_absent(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    log = _log_with_root_created("r1", root["root_hash"])  # solo EVIDENCE_ROOT_CREATED, sin ACTION_ROLLED_BACK

    result = replay_and_verify(
        run_id="r1",
        manifests=manifests,
        evidence_root=root,
        log=log,
        required_event_types=frozenset({"EVIDENCE_ROOT_CREATED", "ACTION_ROLLED_BACK"}),
    )
    assert result.state == "INCOMPLETE"
    assert "ACTION_ROLLED_BACK" in result.detail


def test_replay_only_counts_events_for_the_matching_run_id():
    """Eventos de OTRO run_id en el mismo log no deben contar como
    evidencia de completitud de este run -- cada run se verifica sobre
    su propia porción de la cadena, no sobre toda la cadena compartida."""
    log = TransparencyLog()
    log.append(event_type="EVIDENCE_ROOT_CREATED", object_id="other-run", object_hash="sha256:" + "a" * 64, run_id="OTHER-RUN", producer="test")

    result = replay_and_verify(run_id="r1", manifests=[], evidence_root=build_evidence_root([], run_id="r1", producer="test"), log=log)
    assert result.state == "INCOMPLETE"


def test_replay_ok_property_is_only_true_for_verified():
    from evidence_root.replay import ReplayResult

    for state in ("INCOMPLETE", "HASH_MISMATCH", "BROKEN_CHAIN", "MISSING_ARTIFACT"):
        assert ReplayResult(state=state, detail="x").ok is False
    assert ReplayResult(state="VERIFIED", detail="x").ok is True
