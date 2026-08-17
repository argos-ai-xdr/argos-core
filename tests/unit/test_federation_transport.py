from __future__ import annotations

from federation.federated_artifact import build_federated_artifact
from federation.transport import InProcessTestTransport


def _artifact(**overrides):
    base = {
        "artifact_type": "IOC", "origin_instance": "argos-remote-1", "origin_domain": "domain-remote",
        "origin_tenant": "tenant-remote", "origin_classification": "internal", "payload": {"ioc": "1.2.3.4"},
    }
    base.update(overrides)
    return build_federated_artifact(**base)


def test_transport_label_is_explicitly_test_local():
    """Estructural: nadie puede confundir este transporte con uno real
    -- el propio objeto lo declara, no solo un comentario en el código."""
    transport = InProcessTestTransport()
    assert transport.label.mode == "TEST_LOCAL"


def test_sent_artifact_is_receivable():
    transport = InProcessTestTransport()
    artifact = _artifact()
    transport.send(artifact, destination_instance="argos-local-1")
    received = transport.receive()
    assert received == (artifact,)


def test_receive_drains_the_inbox():
    transport = InProcessTestTransport()
    transport.send(_artifact(), destination_instance="argos-local-1")
    transport.receive()
    assert transport.receive() == ()


def test_outbox_records_destination():
    transport = InProcessTestTransport()
    artifact = _artifact()
    transport.send(artifact, destination_instance="argos-local-1")
    assert transport.outbox() == (("argos-local-1", artifact),)
