from __future__ import annotations

import json

from federation.sanitizer import REDACTED_PLACEHOLDER, SanitizationRule, apply_sanitization


def test_remove_field_deterministically_strips_field():
    payload = {"ioc": "1.2.3.4", "reporter_email": "analyst@example.com"}
    rules = (SanitizationRule(field_path="reporter_email", operation="REMOVE_FIELD"),)
    result = apply_sanitization(payload, rules)
    assert "reporter_email" not in result.released_payload
    assert result.fields_removed == ("reporter_email",)


def test_same_payload_same_policy_yields_identical_released_hash():
    payload = {"a": 1, "b": {"c": 2}}
    rules = (SanitizationRule(field_path="a", operation="REDACT_FIELD"),)
    r1 = apply_sanitization(payload, rules)
    r2 = apply_sanitization(payload, rules)
    assert r1.released_hash == r2.released_hash
    assert r1.original_hash == r2.original_hash


def test_redact_field_replaces_with_placeholder_not_removal():
    payload = {"note": "secret detail"}
    result = apply_sanitization(payload, (SanitizationRule(field_path="note", operation="REDACT_FIELD"),))
    assert result.released_payload["note"] == REDACTED_PLACEHOLDER
    assert result.fields_removed == ()  # redactado, no eliminado -- distinción real


def test_tokenize_field_is_deterministic_and_reversible_is_not_possible_from_output():
    payload = {"user_id": "alice"}
    result1 = apply_sanitization(payload, (SanitizationRule(field_path="user_id", operation="TOKENIZE_FIELD"),))
    result2 = apply_sanitization(payload, (SanitizationRule(field_path="user_id", operation="TOKENIZE_FIELD"),))
    assert result1.released_payload["user_id"] == result2.released_payload["user_id"]
    assert result1.released_payload["user_id"] != "alice"
    assert "alice" not in result1.released_payload["user_id"]


def test_generalize_value_replaces_with_provided_detail():
    payload = {"ip": "10.1.2.3"}
    result = apply_sanitization(payload, (SanitizationRule(field_path="ip", operation="GENERALIZE_VALUE", detail="10.0.0.0/8"),))
    assert result.released_payload["ip"] == "10.0.0.0/8"


def test_drop_attachment_removes_field_like_remove():
    payload = {"attachment_ref": "blob://xyz", "ioc": "1.2.3.4"}
    result = apply_sanitization(payload, (SanitizationRule(field_path="attachment_ref", operation="DROP_ATTACHMENT"),))
    assert "attachment_ref" not in result.released_payload
    assert "attachment_ref" in result.fields_removed


def test_nested_one_level_field_is_sanitized():
    payload = {"metadata": {"internal_note": "sensitive"}, "ioc": "1.2.3.4"}
    result = apply_sanitization(payload, (SanitizationRule(field_path="metadata.internal_note", operation="REMOVE_FIELD"),))
    assert "internal_note" not in result.released_payload["metadata"]


def test_rule_for_absent_field_is_a_deterministic_no_op():
    payload = {"ioc": "1.2.3.4"}
    result = apply_sanitization(payload, (SanitizationRule(field_path="does_not_exist", operation="REMOVE_FIELD"),))
    assert result.transformations == ()
    assert result.released_payload == payload


def test_removed_field_cannot_reappear_from_hidden_duplicate_metadata():
    """Regresión de datos ocultos (§13 del prompt): un campo sensible
    duplicado en dos rutas debe eliminarse en AMBAS rutas declaradas por
    la política -- si la política solo cubre una, la otra sigue presente
    (no hay "magia" que lo detecte), pero una vez la política declara
    ambas rutas, el valor no puede reaparecer en ningún lugar del
    payload liberado."""
    secret = "analyst@example.com"  # pragma: allowlist secret -- variable de prueba, no una credencial real
    payload = {"reporter_email": secret, "metadata": {"reporter_email_copy": secret}}

    partial_rules = (SanitizationRule(field_path="reporter_email", operation="REMOVE_FIELD"),)
    partial_result = apply_sanitization(payload, partial_rules)
    assert secret in json.dumps(partial_result.released_payload)  # la copia oculta NO declarada sigue ahí

    full_rules = (
        SanitizationRule(field_path="reporter_email", operation="REMOVE_FIELD"),
        SanitizationRule(field_path="metadata.reporter_email_copy", operation="REMOVE_FIELD"),
    )
    full_result = apply_sanitization(payload, full_rules)
    assert secret not in json.dumps(full_result.released_payload)


def test_original_payload_is_not_mutated():
    payload = {"a": 1}
    apply_sanitization(payload, (SanitizationRule(field_path="a", operation="REMOVE_FIELD"),))
    assert payload == {"a": 1}
