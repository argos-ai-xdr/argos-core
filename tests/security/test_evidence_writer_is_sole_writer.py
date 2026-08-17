"""Chequeo estático real (ADR-006/ADR-016: evidence_writer es la única
escritura permitida al evidence store; ADR-057 extiende la misma regla a
evidence_root/transparency_log): ningún otro módulo de services/
construye una referencia ceph:// directamente, ni expone una forma de
borrar o reescribir una entrada de evidencia/transparencia ya creada.
"""
from __future__ import annotations

import pathlib

import pytest
from evidence_root.transparency_log import TransparencyLog

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


def test_transparency_log_has_no_public_delete_or_edit_method():
    """Fase J (ADR-057): ningún agente puede modificar o borrar
    evidencia/transparencia histórica -- la API pública de TransparencyLog
    no debe crecer nunca un método delete/remove/edit/update/clear."""
    forbidden_substrings = ("delete", "remove", "edit", "update", "clear", "truncate", "overwrite")
    public_methods = [name for name in dir(TransparencyLog) if not name.startswith("_")]
    offenders = [m for m in public_methods if any(f in m.lower() for f in forbidden_substrings)]
    assert offenders == [], f"TransparencyLog no debe exponer métodos de borrado/edición: {offenders}"


def test_evidence_root_and_transparency_log_modules_never_import_recommendation_engines():
    """El productor de evidencia/transparencia debe ser determinista/no
    generativo (paso 3 del prompt): ni evidence_root ni transparency_log
    deben importar recommendation (el único componente con salida
    generativa potencial, LangGraphEngine) -- estructuralmente, no solo
    por convención."""
    evidence_root_dir = SERVICES_DIR / "evidence_root"
    for path in evidence_root_dir.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "import recommendation" not in text, f"{path} no debe importar recommendation"


def test_transparency_entry_fields_are_frozen():
    """No hay ninguna vía pública para reasignar un campo de una entrada
    ya creada (dataclass frozen=True) -- mutarla exige acceso directo a
    la lista interna (_entries), nunca a través de la API pública."""
    log = TransparencyLog()
    entry = log.append(event_type="ACTION_EXECUTED", object_id="act-1", object_hash="sha256:" + "a" * 64, run_id="r1", producer="test")
    with pytest.raises(AttributeError):
        entry.object_hash = "sha256:" + "f" * 64


def test_recommendation_has_no_credentials_field_in_its_module():
    """Chequeo léxico simple: el módulo recommendation no debe declarar
    nada que suene a credencial de ejecución (ADR-005/ADR-011)."""
    text = (SERVICES_DIR / "recommendation" / "__init__.py").read_text(encoding="utf-8")
    for forbidden in ("api_key", "access_token", "kubeconfig", "private_key"):
        assert forbidden not in text.lower()
