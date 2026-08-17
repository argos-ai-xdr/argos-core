"""federation.security_domain: SecurityDomain v1 y aislamiento tenant/
dominio (ADR pendiente de asignar tras inspección del registro, Fase L;
prompt maestro de arquitectura objetivo, "SECURITY DOMAIN").

**Invariante crítico, aplicado en código**: `object.security_domain !=
target.security_domain` NUNCA implica que la transferencia esté
permitida. `transfer_allowed` es deny-by-default — solo permite lo que
`allowed_destinations`/`allowed_federation` declaran explícitamente,
nunca infiere permiso de la ausencia de una prohibición.

Reutiliza el enum `classification` real ya usado en el envelope común
(`internal`/`confidential`/`restricted`, ADR-001) — no inventa una
taxonomía de clasificación paralela.
"""
from __future__ import annotations

import dataclasses

CLASSIFICATION_LEVELS = ("internal", "confidential", "restricted")


class UnknownClassification(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class SecurityDomain:
    tenant_id: str
    domain_id: str
    classification: str
    trust_zone: str
    policy_domain: str
    evidence_domain: str
    knowledge_domain: str
    allowed_federation: frozenset[str]  # domain_id de pares con los que SÍ se federa
    allowed_destinations: frozenset[str]  # domain_id a los que SÍ se puede transferir
    retention_profile: str
    export_policy: str

    def __post_init__(self) -> None:
        if self.classification not in CLASSIFICATION_LEVELS:
            raise UnknownClassification(f"{self.classification!r} no es una clasificación real: {CLASSIFICATION_LEVELS}")


def transfer_allowed(source: SecurityDomain, destination: SecurityDomain) -> tuple[bool, str]:
    """Deny-by-default real: la transferencia solo se permite si el
    dominio destino está EXPLÍCITAMENTE en `allowed_destinations` del
    origen. Dominios iguales (mismo domain_id) se permiten trivialmente
    -- no es una transferencia cross-domain."""
    if source.domain_id == destination.domain_id:
        return True, "mismo domain_id: no es una transferencia cross-domain"
    if destination.domain_id in source.allowed_destinations:
        return True, f"{destination.domain_id!r} está en allowed_destinations de {source.domain_id!r}"
    return False, f"{destination.domain_id!r} NO está en allowed_destinations de {source.domain_id!r} (deny-by-default)"


def federation_allowed(local: SecurityDomain, remote_domain_id: str) -> tuple[bool, str]:
    """Mismo criterio deny-by-default para aceptar federación de un peer
    remoto: el domain_id remoto debe estar en `allowed_federation` del
    dominio local."""
    if remote_domain_id in local.allowed_federation:
        return True, f"{remote_domain_id!r} está en allowed_federation de {local.domain_id!r}"
    return False, f"{remote_domain_id!r} NO está en allowed_federation de {local.domain_id!r} (deny-by-default)"
