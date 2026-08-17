from __future__ import annotations

import pytest
from federation.ledger import ContentConflict, FederationLedger
from federation.revocation import RevocationRegistry


def test_ledger_first_sighting_is_recorded():
    ledger = FederationLedger()
    assert ledger.check_and_record("art-1", "sha256:" + "a" * 64) is True
    assert ledger.already_seen("art-1", "sha256:" + "a" * 64)


def test_ledger_same_artifact_same_hash_is_idempotent():
    ledger = FederationLedger()
    ledger.check_and_record("art-1", "sha256:" + "a" * 64)
    assert ledger.check_and_record("art-1", "sha256:" + "a" * 64) is True  # reintento, no un error


def test_ledger_same_id_different_hash_raises_content_conflict():
    ledger = FederationLedger()
    ledger.check_and_record("art-1", "sha256:" + "a" * 64)
    with pytest.raises(ContentConflict):
        ledger.check_and_record("art-1", "sha256:" + "f" * 64)


def test_revocation_registry_starts_clean():
    reg = RevocationRegistry()
    assert not reg.is_revoked("art-1")
    assert reg.revoked_at("art-1") is None


def test_revoke_is_reflected_immediately():
    reg = RevocationRegistry()
    reg.revoke("art-1", revoked_at="2026-08-17T10:00:00Z", reason="fuente comprometida")
    assert reg.is_revoked("art-1")
    assert reg.revoked_at("art-1") == "2026-08-17T10:00:00Z"
    assert reg.reason_for("art-1") == "fuente comprometida"


def test_revocation_registry_has_no_unrevoke_method():
    public_methods = {name for name in dir(RevocationRegistry) if not name.startswith("_")}
    assert public_methods == {"revoke", "is_revoked", "revoked_at", "reason_for"}
