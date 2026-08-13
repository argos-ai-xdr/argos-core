"""Chequeo estático real (ADR-006/ADR-016: evidence_writer es la única
escritura permitida al evidence store): ningún otro módulo de services/
construye una referencia ceph:// directamente.
"""
from __future__ import annotations

import pathlib

SERVICES_DIR = pathlib.Path(__file__).resolve().parents[2] / "services"


def test_no_service_other_than_evidence_writer_references_ceph_directly():
    offenders = []
    for path in SERVICES_DIR.rglob("*.py"):
        if path.parent.name == "evidence_writer":
            continue
        text = path.read_text(encoding="utf-8")
        if "ceph://" in text:
            offenders.append(str(path))
    assert offenders == [], f"solo evidence_writer debe construir referencias ceph://, encontrado en: {offenders}"


def test_recommendation_has_no_credentials_field_in_its_module():
    """Chequeo léxico simple: el módulo recommendation no debe declarar
    nada que suene a credencial de ejecución (ADR-005/ADR-011)."""
    text = (SERVICES_DIR / "recommendation" / "__init__.py").read_text(encoding="utf-8")
    for forbidden in ("api_key", "access_token", "kubeconfig", "private_key"):
        assert forbidden not in text.lower()
