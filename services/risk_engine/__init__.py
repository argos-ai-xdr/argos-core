"""risk-engine: ranking explicable a partir de VulnerabilityFinding + la
criticidad ESP del AssetSnapshot correspondiente (exposición, criticidad,
KEV, EPSS, fix disponible — documento maestro v0.5, servicios principales).

Gate G2 (argos-control/governance/gates/gates.md): "ranking explica hechos,
fuentes y hashes; sin inferencias falsas" — por eso RiskScore.explanation
siempre incluye los factores usados y RiskScore nunca inventa una
criticidad para un activo que no está en `assets_by_id` (lo trata como
desconocido y lo penaliza explícitamente, no lo ignora en silencio).
"""
from __future__ import annotations

import dataclasses

_CRITICALITY_WEIGHT = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}
_UNKNOWN_CRITICALITY_WEIGHT = 0.5  # penaliza lo desconocido, no lo trata como "low" confiado
_KEV_MULTIPLIER = 3.0
_FIX_AVAILABLE_DISCOUNT = 0.5


@dataclasses.dataclass(frozen=True)
class RiskScore:
    finding_id: str
    score: float
    explanation: dict


def score_finding(finding: dict, asset: dict | None) -> RiskScore:
    epss = finding.get("epss", 0.0)
    kev = bool(finding.get("kev"))
    fix_available = bool(finding.get("fix_available"))

    if asset is not None and "criticality_esp" in asset:
        criticality = asset["criticality_esp"]
        criticality_weight = _CRITICALITY_WEIGHT.get(criticality, _UNKNOWN_CRITICALITY_WEIGHT)
        criticality_source = asset.get("asset_id", "?")
    else:
        criticality = "unknown"
        criticality_weight = _UNKNOWN_CRITICALITY_WEIGHT
        criticality_source = None

    kev_multiplier = _KEV_MULTIPLIER if kev else 1.0
    fix_factor = _FIX_AVAILABLE_DISCOUNT if fix_available else 1.0

    score = epss * kev_multiplier * criticality_weight * fix_factor

    return RiskScore(
        finding_id=finding.get("finding_id", "?"),
        score=score,
        explanation={
            "epss": epss,
            "kev": kev,
            "kev_multiplier": kev_multiplier,
            "asset_criticality": criticality,
            "criticality_weight": criticality_weight,
            "criticality_source_asset_id": criticality_source,
            "fix_available": fix_available,
            "fix_factor": fix_factor,
            "source_ref": finding.get("source_ref"),
        },
    )


def rank_findings(findings: list[dict], assets_by_id: dict[str, dict]) -> list[RiskScore]:
    """Orden descendente por score. `assets_by_id` es opcional-por-entrada:
    un finding cuyo asset_id no está en el diccionario se puntúa con
    _UNKNOWN_CRITICALITY_WEIGHT, nunca se descarta ni se asume "low"."""
    scored = [score_finding(f, assets_by_id.get(f.get("asset_id", ""))) for f in findings]
    return sorted(scored, key=lambda r: r.score, reverse=True)
