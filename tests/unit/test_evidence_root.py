from __future__ import annotations

import pytest
from evidence_root import (
    InconsistentEvidenceRoot,
    MissingCriticalEvidence,
    build_evidence_root,
    recompute_root_hash,
    verify_evidence_root,
)
from evidence_writer import EvidenceWriter, RetentionPolicy


def _manifests(contracts_path, context, contents: list[bytes]) -> list[dict]:
    writer = EvidenceWriter(contracts_path, context)
    return [writer.write_bytes(c, media_type="text/plain", retention=RetentionPolicy(policy="7d")) for c in contents]


def test_root_is_deterministic_for_the_same_artifact_set(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a", b"b", b"c"])
    root1 = build_evidence_root(manifests, run_id="r1", producer="test")
    root2 = build_evidence_root(manifests, run_id="r1", producer="test")
    assert root1["root_hash"] == root2["root_hash"]
    assert root1["root_id"] != root2["root_id"]  # el wrapper difiere, el hash del conjunto no


def test_root_input_order_does_not_affect_the_hash(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a", b"b", b"c"])
    forward = build_evidence_root(manifests, run_id="r1", producer="test")
    backward = build_evidence_root(list(reversed(manifests)), run_id="r1", producer="test")
    assert forward["root_hash"] == backward["root_hash"]


def test_root_changes_if_any_artifact_content_changes(contracts_path, context):
    manifests_a = _manifests(contracts_path, context, [b"a", b"b"])
    manifests_b = _manifests(contracts_path, context, [b"a", b"DIFFERENT"])
    root_a = build_evidence_root(manifests_a, run_id="r1", producer="test")
    root_b = build_evidence_root(manifests_b, run_id="r1", producer="test")
    assert root_a["root_hash"] != root_b["root_hash"]


def test_root_changes_if_an_artifact_is_added_or_removed(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a", b"b"])
    root_two = build_evidence_root(manifests, run_id="r1", producer="test")
    root_three = build_evidence_root(manifests + _manifests(contracts_path, context, [b"c"]), run_id="r1", producer="test")
    assert root_two["root_hash"] != root_three["root_hash"]
    assert root_two["artifact_count"] == 2
    assert root_three["artifact_count"] == 3


def test_root_excludes_volatile_wrapper_fields_from_the_hash(contracts_path, context):
    """root_hash depende SOLO de artifact_refs -- created_at/root_id
    (volátiles, distintos en cada construcción) nunca entran en el
    material hasheado, si no build_evidence_root nunca sería
    determinista para el mismo conjunto (ver test de determinismo)."""
    manifests = _manifests(contracts_path, context, [b"a"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    assert root["root_hash"] == recompute_root_hash(root)


def test_exact_duplicate_manifest_is_deduplicated_not_an_error(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a"])
    duplicated = manifests + manifests  # mismo artifact_id, mismo sha256, referenciado dos veces
    root = build_evidence_root(duplicated, run_id="r1", producer="test")
    assert root["artifact_count"] == 1


def test_conflicting_duplicate_artifact_id_always_raises(contracts_path, context):
    """Dos manifiestos con el MISMO artifact_id pero sha256 distinto --
    corrupción real, nunca se resuelve en silencio eligiendo uno."""
    m1, m2 = _manifests(contracts_path, context, [b"a", b"b"])
    conflicting = {**m2, "artifact_id": m1["artifact_id"]}
    with pytest.raises(InconsistentEvidenceRoot):
        build_evidence_root([m1, conflicting], run_id="r1", producer="test")


def test_missing_manifest_in_critical_mode_raises(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a"])
    with pytest.raises(MissingCriticalEvidence):
        build_evidence_root([*manifests, None], run_id="r1", producer="test", critical=True)


def test_missing_manifest_in_non_critical_mode_is_skipped_not_fabricated(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a"])
    root = build_evidence_root([*manifests, None], run_id="r1", producer="test", critical=False)
    assert root["artifact_count"] == 1  # el hueco se omite, nunca se inventa un artefacto "UNKNOWN"


def test_verify_evidence_root_true_for_untampered_root(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a", b"b"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    assert verify_evidence_root(root) is True


def test_verify_evidence_root_false_if_root_hash_was_tampered(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a", b"b"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    tampered = {**root, "root_hash": "sha256:" + "0" * 64}
    assert verify_evidence_root(tampered) is False


def test_verify_evidence_root_false_if_an_artifact_ref_was_tampered(contracts_path, context):
    """Alguien reescribe artifact_refs (p. ej. sustituye un sha256) sin
    actualizar root_hash -- debe detectarse, no solo cuando root_hash
    mismo cambia."""
    manifests = _manifests(contracts_path, context, [b"a", b"b"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    tampered_refs = [{**ref, "sha256": "f" * 64} if i == 0 else ref for i, ref in enumerate(root["artifact_refs"])]
    tampered = {**root, "artifact_refs": tampered_refs}
    assert verify_evidence_root(tampered) is False


def test_algorithm_and_canonicalization_are_explicit_not_implicit(contracts_path, context):
    """Crypto-agility: un root futuro con otro algoritmo debe poder
    declararlo sin romper el contrato -- por eso son campos explícitos,
    no una constante oculta en el código del consumidor."""
    manifests = _manifests(contracts_path, context, [b"a"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    assert root["algorithm"] == "sha256"
    assert root["canonicalization"]


def test_each_leaf_resolves_to_its_artifact(contracts_path, context):
    manifests = _manifests(contracts_path, context, [b"a", b"b"])
    root = build_evidence_root(manifests, run_id="r1", producer="test")
    manifest_by_id = {m["artifact_id"]: m for m in manifests}
    for ref in root["artifact_refs"]:
        assert ref["artifact_id"] in manifest_by_id
        assert ref["sha256"] == manifest_by_id[ref["artifact_id"]]["sha256"]
        assert ref["object_ref"] == manifest_by_id[ref["artifact_id"]]["object_ref"]


def test_empty_manifest_list_produces_a_root_with_zero_artifacts(contracts_path, context):
    root = build_evidence_root([], run_id="r1", producer="test")
    assert root["artifact_count"] == 0
    assert verify_evidence_root(root) is True
