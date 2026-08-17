"""federation.ifc: control de flujo de información (Information Flow
Control) para transferencias cross-domain (Fase L; prompt maestro de
arquitectura objetivo, §11, "IFC").

No existía ningún mecanismo de IFC/taint previo en el repositorio (§11
del prompt lo confirma explícitamente: "integrate with existing (none
exists)") -- este módulo es nuevo, no una extensión de algo ya presente.

`evaluate_ifc` es una función pura, determinista, basada exclusivamente
en el enum real de clasificación (`security_domain.CLASSIFICATION_LEVELS`)
y en las reglas de `security_domain.transfer_allowed`. **Ningún LLM
participa en esta decisión** -- una IA NUNCA puede desclasificar de forma
autoritativa (§10 del prompt): la única forma de bajar de clasificación
(`requested < original`) es `REQUIRE_APPROVAL`, nunca `ALLOW`/`SANITIZE`
automático.
"""
from __future__ import annotations

import dataclasses
from typing import Literal

from federation.security_domain import (
    CLASSIFICATION_LEVELS,
    SecurityDomain,
    UnknownClassification,
    transfer_allowed,
)

IFCOutcome = Literal["ALLOW", "DENY", "SANITIZE", "REQUIRE_APPROVAL"]


@dataclasses.dataclass(frozen=True)
class IFCLabel:
    """Etiqueta que se propaga junto al dato -- exactamente los ejes que
    pide el prompt: classification/origin/purpose/domain/handling/
    exportability/retention/trust."""

    classification: str
    origin: str
    purpose: str
    domain: str
    handling: str
    exportability: str
    retention_profile: str
    trust: str

    def __post_init__(self) -> None:
        if self.classification not in CLASSIFICATION_LEVELS:
            raise UnknownClassification(f"{self.classification!r} no es una clasificación real: {CLASSIFICATION_LEVELS}")


@dataclasses.dataclass(frozen=True)
class IFCDecision:
    outcome: IFCOutcome
    reason_codes: tuple[str, ...]
    label: IFCLabel
    requested_classification: str


def evaluate_ifc(
    *,
    label: IFCLabel,
    source_domain: SecurityDomain,
    destination_domain: SecurityDomain,
    requested_classification: str | None = None,
) -> IFCDecision:
    target_classification = requested_classification or label.classification
    if target_classification not in CLASSIFICATION_LEVELS:
        raise UnknownClassification(f"{target_classification!r} no es una clasificación real: {CLASSIFICATION_LEVELS}")

    domain_ok, domain_reason = transfer_allowed(source_domain, destination_domain)
    if not domain_ok:
        return IFCDecision(outcome="DENY", reason_codes=("DOMAIN_TRANSFER_NOT_ALLOWED", domain_reason), label=label, requested_classification=target_classification)

    if label.exportability == "forbidden":
        return IFCDecision(outcome="DENY", reason_codes=("EXPORTABILITY_FORBIDDEN",), label=label, requested_classification=target_classification)

    original_rank = CLASSIFICATION_LEVELS.index(label.classification)
    requested_rank = CLASSIFICATION_LEVELS.index(target_classification)

    if requested_rank < original_rank:
        # Downgrade attack surface (§29 del prompt): pedir liberar un dato
        # bajo una etiqueta MENOS restrictiva que la original nunca se
        # concede automáticamente, sin importar quién o qué lo solicite.
        return IFCDecision(outcome="REQUIRE_APPROVAL", reason_codes=("CLASSIFICATION_DOWNGRADE_REQUESTED",), label=label, requested_classification=target_classification)

    if label.trust in ("UNTRUSTED", "UNKNOWN"):
        return IFCDecision(outcome="REQUIRE_APPROVAL", reason_codes=(f"ORIGIN_TRUST_{label.trust}",), label=label, requested_classification=target_classification)

    if destination_domain.classification != label.classification:
        # Cruza a un dominio con línea base de clasificación distinta:
        # se permite, pero solo tras sanitización determinista, nunca en
        # crudo.
        return IFCDecision(outcome="SANITIZE", reason_codes=("CROSS_CLASSIFICATION_DOMAIN",), label=label, requested_classification=target_classification)

    return IFCDecision(outcome="ALLOW", reason_codes=(), label=label, requested_classification=target_classification)
