from __future__ import annotations

import pytest
from federation.federated_artifact import (
    ForbiddenDefaultTrust,
    UnknownArtifactType,
    UnknownTrustLabel,
    build_federated_artifact,
    verify_content_hash,
)


def _artifact(**overrides):
    base = {
        "artifact_type": "DetectionRule",
        "origin_instance": "argos-remote-1",
        "origin_domain": "domain-remote",
        "origin_tenant": "tenant-remote",
        "origin_classification": "internal",
        "payload": {"rule": "detect X", "version": 1},
    }
    base.update(overrides)
    return build_federated_artifact(**base)


def test_content_hash_is_real_and_verifiable():
    artifact = _artifact()
    assert verify_content_hash(artifact)


def test_content_hash_changes_with_payload():
    a1 = _artifact(payload={"rule": "A"})
    a2 = _artifact(payload={"rule": "B"})
    assert a1.content_hash != a2.content_hash


def test_tampered_payload_fails_content_hash_verification():
    """Simula lo que pasaría si alguien reescribe el payload después de
    construir el artefacto sin actualizar content_hash."""
    import dataclasses

    artifact = _artifact()
    tampered = dataclasses.replace(artifact, payload={"rule": "TAMPERED"})
    assert not verify_content_hash(tampered)


def test_unknown_artifact_type_is_rejected():
    with pytest.raises(UnknownArtifactType):
        _artifact(artifact_type="NotARealType")


def test_authoritative_origin_trust_is_forbidden_on_ingest():
    """§12 del prompt: un artefacto federado NUNCA se construye con
    origin_trust=AUTHORITATIVE -- ni siquiera si el llamante lo pide
    explícitamente, porque esa promoción debe ser un acto local
    posterior, nunca un valor que el propio ingreso pueda fijar."""
    with pytest.raises(ForbiddenDefaultTrust):
        _artifact(origin_trust="AUTHORITATIVE")


def test_unknown_trust_label_is_rejected():
    with pytest.raises(UnknownTrustLabel):
        _artifact(origin_trust="SUPER_TRUSTED")


@pytest.mark.parametrize("trust_label", ["TRUSTED", "EXTERNAL", "UNTRUSTED", "UNKNOWN"])
def test_all_ingestable_trust_labels_are_accepted(trust_label):
    artifact = _artifact(origin_trust=trust_label)
    assert artifact.origin_trust == trust_label


def test_default_origin_trust_is_external_not_authoritative():
    artifact = _artifact()
    assert artifact.origin_trust == "EXTERNAL"


def test_artifact_id_and_created_at_are_generated_not_supplied():
    artifact = _artifact()
    assert artifact.artifact_id.startswith("fedart-")
    assert artifact.created_at


def test_to_dict_is_json_serializable():
    import json

    artifact = _artifact()
    json.dumps(artifact.to_dict())  # no debe lanzar
