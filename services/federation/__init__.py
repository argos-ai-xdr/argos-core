"""federation: Federación / Cross-Domain (Fase L; prompt maestro de
arquitectura objetivo, "FEDERATION CORE").

**Principio central: la federación transporta información, nunca
autoridad.** Ninguna instancia remota de ARGOS puede conceder de forma
remota un ALLOW de OPA, una Approval de HITL, validez de SafetyEnvelope,
autoridad de ejecución, ni promoción local a ACTIVE. Invariante:
`REMOTE TRUST != LOCAL AUTHORITY`.

Submódulos:
- `security_domain`: `SecurityDomain` v1, aislamiento tenant/domain
  deny-by-default (`transfer_allowed`, `federation_allowed`).
- `federated_artifact`: `FederatedArtifact` v1, hash de contenido
  determinista, `origin_trust` nunca `AUTHORITATIVE` por defecto.
- `ledger`: anti-replay (`FederationLedger`, §17).
- `revocation`: revocación real, sin "des-revocar" (`RevocationRegistry`, §18).
- `decision`: evaluación local de confianza + `FederationDecision`
  (ACCEPT/QUARANTINE/REJECT/LOCAL_REVALIDATION_REQUIRED; §6, §7).
"""
from __future__ import annotations
