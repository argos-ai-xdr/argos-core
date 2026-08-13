from __future__ import annotations

import pytest
from argos_envelope import EnvelopeContext, build_envelope, new_id_prefixed, sha256_of_payload


@pytest.mark.parametrize("prefix", ["e", "evt", "inc", "reco", "case", "art", "pol", "vf", "asn"])
def test_new_id_prefixed_always_fits_envelope_pattern(prefix):
    """Regresión: 'reco-' + hex de 32 daba 37 caracteres, por encima del
    máximo 36 del pattern del envelope (^[0-9A-Za-z-]{20,36}$) — encontrado
    probando services/recommendation contra el schema real."""
    identifier = new_id_prefixed(prefix)
    assert 20 <= len(identifier) <= 36
    assert identifier.startswith(f"{prefix}-")


def test_new_id_prefixed_rejects_too_long_prefix():
    with pytest.raises(ValueError):
        new_id_prefixed("a" * 20)


def test_sha256_of_payload_is_deterministic_regardless_of_key_order():
    a = sha256_of_payload({"x": 1, "y": 2})
    b = sha256_of_payload({"y": 2, "x": 1})
    assert a == b
    assert a.startswith("sha256:")


def test_build_envelope_omits_optional_fields_when_absent():
    ctx = EnvelopeContext(producer="p", run_id="r")
    envelope = build_envelope(ctx, {}, message_id="evt-x")
    assert "trace_id" not in envelope
    assert "native_ref" not in envelope
