from __future__ import annotations

import hashlib

from evidence_writer import EvidenceWriter, RetentionPolicy


def test_write_bytes_hashes_real_content(contracts_path, context):
    writer = EvidenceWriter(contracts_path, context)
    manifest = writer.write_bytes(b"hello", media_type="text/plain", retention=RetentionPolicy(policy="7d"))
    assert manifest["sha256"] == hashlib.sha256(b"hello").hexdigest()


def test_different_content_yields_different_hash_and_object_ref(contracts_path, context):
    writer = EvidenceWriter(contracts_path, context)
    m1 = writer.write_bytes(b"a", media_type="text/plain", retention=RetentionPolicy(policy="7d"))
    m2 = writer.write_bytes(b"b", media_type="text/plain", retention=RetentionPolicy(policy="7d"))
    assert m1["sha256"] != m2["sha256"]
    assert m1["object_ref"] != m2["object_ref"]


def test_retention_expires_at_is_optional(contracts_path, context):
    writer = EvidenceWriter(contracts_path, context)
    manifest = writer.write_bytes(b"x", media_type="text/plain", retention=RetentionPolicy(policy="none"))
    assert "expires_at" not in manifest["retention"]
