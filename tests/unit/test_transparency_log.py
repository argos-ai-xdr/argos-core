from __future__ import annotations

import dataclasses
import json
import pathlib

import pytest
from evidence_root.transparency_log import (
    GENESIS_HASH,
    ReceiptNotFound,
    TransparencyLog,
    UnknownEventType,
    load_log,
    verify_receipt,
)


def test_first_entry_chains_from_genesis():
    log = TransparencyLog()
    entry = log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    assert entry.sequence == 0
    assert entry.previous_entry_hash == GENESIS_HASH


def test_entries_chain_to_each_other():
    log = TransparencyLog()
    e1 = log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    e2 = log.append(event_type="ACTION_VERIFIED", object_id="act-1", object_hash="sha256:" + "b" * 64, run_id="r1", producer="test")
    assert e2.sequence == 1
    assert e2.previous_entry_hash == e1.entry_hash


def test_unknown_event_type_is_rejected():
    log = TransparencyLog()
    with pytest.raises(UnknownEventType):
        log.append(event_type="COMPONENT_PROMOTED", object_id="x", object_hash="sha256:" + "0" * 64, run_id="r1", producer="test")


def test_verify_chain_ok_on_untampered_log():
    log = TransparencyLog()
    for i in range(5):
        log.append(event_type="ACTION_EXECUTED", object_id=f"act-{i}", object_hash="sha256:" + str(i) * 64, run_id="r1", producer="test")
    result = log.verify_chain()
    assert result.ok
    assert result.broken_at_sequence is None


def test_verify_chain_empty_log_is_ok():
    assert TransparencyLog().verify_chain().ok


def test_verify_chain_detects_a_mutated_entry_field():
    """El núcleo de tamper-evidence: mutar un campo de una entrada ya
    escrita (acceso directo a la lista interna, simulando compromiso del
    proceso) debe romper entry_hash y detectarse -- LOGICALLY_APPEND_ONLY
    no significa que la mutación sea imposible, significa que es
    detectable."""
    log = TransparencyLog()
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    log.append(event_type="ACTION_VERIFIED", object_id="act-1", object_hash="sha256:" + "b" * 64, run_id="r1", producer="test")

    log._entries[0] = dataclasses.replace(log._entries[0], object_hash="sha256:" + "TAMPERED000000000000000000000000000000000000000000000000")

    result = log.verify_chain()
    assert not result.ok
    assert result.broken_at_sequence == 0


def test_verify_chain_detects_a_broken_previous_hash_link():
    log = TransparencyLog()
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    log.append(event_type="ACTION_VERIFIED", object_id="act-1", object_hash="sha256:" + "b" * 64, run_id="r1", producer="test")

    log._entries[1] = dataclasses.replace(log._entries[1], previous_entry_hash="sha256:" + "f" * 64)

    result = log.verify_chain()
    assert not result.ok
    assert result.broken_at_sequence == 1


def test_verify_chain_detects_a_sequence_gap_from_a_removed_entry():
    """Borrar una entrada de en medio (list.pop directo, nunca expuesto
    en la API pública) deja un hueco de secuencia -- verify_chain debe
    detectarlo porque el previous_entry_hash de la entrada siguiente ya
    no coincide con el hash real de lo que ahora es su predecesora."""
    log = TransparencyLog()
    for i in range(3):
        log.append(event_type="ACTION_EXECUTED", object_id=f"act-{i}", object_hash="sha256:" + str(i) * 64, run_id="r1", producer="test")

    del log._entries[1]  # borra la entrada de en medio

    result = log.verify_chain()
    assert not result.ok


def test_transparency_log_exposes_no_delete_or_mutate_method():
    public_methods = {name for name in dir(TransparencyLog) if not name.startswith("_")}
    assert public_methods == {"append", "entries", "entries_for", "verify_chain", "issue_receipt"}


def test_entries_returns_an_immutable_snapshot():
    log = TransparencyLog()
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    snapshot = log.entries()
    with pytest.raises(TypeError):
        snapshot[0] = None  # tuple -- no se puede reasignar


# ---------------------------------------------------------------------------
# TransparencyReceipt
# ---------------------------------------------------------------------------


def test_issue_receipt_for_existing_object():
    log = TransparencyLog()
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    receipt = log.issue_receipt("act-1")
    assert receipt.object_id == "act-1"
    assert receipt.sequence == 0
    assert verify_receipt(receipt, log) is True


def test_issue_receipt_for_unknown_object_raises():
    log = TransparencyLog()
    with pytest.raises(ReceiptNotFound):
        log.issue_receipt("never-seen")


def test_issue_receipt_uses_the_most_recent_event_for_the_same_object():
    log = TransparencyLog()
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    log.append(event_type="ACTION_VERIFIED", object_id="act-1", object_hash="sha256:" + "b" * 64, run_id="r1", producer="test")
    receipt = log.issue_receipt("act-1")
    assert receipt.event_type == "ACTION_VERIFIED"
    assert receipt.sequence == 1


def test_verify_receipt_fails_if_the_certified_entry_was_mutated():
    log = TransparencyLog()
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    receipt = log.issue_receipt("act-1")

    log._entries[0] = dataclasses.replace(log._entries[0], object_hash="sha256:" + "f" * 64)

    assert verify_receipt(receipt, log) is False


def test_verify_receipt_still_valid_if_chain_breaks_after_its_own_sequence():
    """Un receipt certifica hasta su propia secuencia -- si la cadena se
    rompe DESPUÉS de ese punto, el receipt sigue siendo válido para lo
    que certificó."""
    log = TransparencyLog()
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    receipt = log.issue_receipt("act-1")
    log.append(event_type="ACTION_VERIFIED", object_id="act-2", object_hash="sha256:" + "b" * 64, run_id="r1", producer="test")

    log._entries[1] = dataclasses.replace(log._entries[1], object_hash="sha256:" + "f" * 64)  # rompe DESPUÉS del receipt

    assert log.verify_chain().ok is False
    assert verify_receipt(receipt, log) is True


def test_transparency_receipt_has_no_signature_field():
    log = TransparencyLog()
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    receipt = log.issue_receipt("act-1")
    assert not hasattr(receipt, "signature")


# ---------------------------------------------------------------------------
# Persistencia JSONL (append real a disco)
# ---------------------------------------------------------------------------


def test_persisted_entries_survive_reload(tmp_path: pathlib.Path):
    path = tmp_path / "transparency.jsonl"
    log = TransparencyLog(persist_path=path)
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    log.append(event_type="ACTION_VERIFIED", object_id="act-1", object_hash="sha256:" + "b" * 64, run_id="r1", producer="test")

    reloaded = load_log(path)
    assert len(reloaded.entries()) == 2
    assert reloaded.verify_chain().ok
    assert reloaded.entries() == log.entries()


def test_persist_writes_one_json_line_per_entry(tmp_path: pathlib.Path):
    path = tmp_path / "transparency.jsonl"
    log = TransparencyLog(persist_path=path)
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    log.append(event_type="ACTION_EXECUTED", object_id="act-2", object_hash="sha256:" + "b" * 64, run_id="r1", producer="test")

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["object_id"] == "act-1"


def test_reloaded_log_detects_manual_tampering_of_the_file(tmp_path: pathlib.Path):
    path = tmp_path / "transparency.jsonl"
    log = TransparencyLog(persist_path=path)
    log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    log.append(event_type="ACTION_VERIFIED", object_id="act-1", object_hash="sha256:" + "b" * 64, run_id="r1", producer="test")

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered_first = json.loads(lines[0])
    tampered_first["object_hash"] = "sha256:" + "f" * 64
    lines[0] = json.dumps(tampered_first)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reloaded = load_log(path)
    assert not reloaded.verify_chain().ok


def test_load_log_missing_file_returns_empty_log(tmp_path: pathlib.Path):
    log = load_log(tmp_path / "does-not-exist.jsonl")
    assert log.entries() == ()
    assert log.verify_chain().ok
