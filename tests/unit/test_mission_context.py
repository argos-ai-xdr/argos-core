from __future__ import annotations

from mission_context import assess_blast_radius, build_mission_context


def test_build_mission_context_with_full_data():
    ctx = build_mission_context(
        "asset-x", source_id="mission-registry", criticality="high", crown_jewel=True,
        acceptable_degradation="read-only for 1h", maximum_outage="PT2H", recovery_priority=1,
        dependencies=("asset-y", "asset-z"),
    )
    assert ctx.has_sufficient_context
    assert ctx.crown_jewel is True


def test_mission_context_without_criticality_or_crown_jewel_is_insufficient():
    ctx = build_mission_context("asset-x", source_id="mission-registry")
    assert not ctx.has_sufficient_context


# ---------------------------------------------------------------------------
# Invariante central: UNKNOWN != impacto cero.
# ---------------------------------------------------------------------------


def test_no_mission_context_is_insufficient_context_not_none():
    result = assess_blast_radius(mission_context=None, technical_affected_count=5)
    assert result.mission_blast_radius == "INSUFFICIENT_CONTEXT"
    assert result.mission_blast_radius != "NONE"


def test_mission_context_without_sufficient_data_is_insufficient_context():
    ctx = build_mission_context("asset-x", source_id="s")  # sin criticality/crown_jewel
    result = assess_blast_radius(mission_context=ctx, technical_affected_count=3)
    assert result.mission_blast_radius == "INSUFFICIENT_CONTEXT"


def test_missing_technical_count_is_insufficient_context_even_with_full_mission_data():
    ctx = build_mission_context("asset-x", source_id="s", criticality="critical", crown_jewel=True)
    result = assess_blast_radius(mission_context=ctx, technical_affected_count=None)
    assert result.mission_blast_radius == "INSUFFICIENT_CONTEXT"
    assert result.operational_blast_radius == "INSUFFICIENT_CONTEXT"


def test_zero_technical_impact_is_genuinely_none_not_insufficient():
    """Distinto del caso anterior: aquí SÍ hay contexto completo Y se
    calculó blast radius técnico, y dio 0 -- eso es NONE real, no
    INSUFFICIENT_CONTEXT (la ausencia de dato es distinta de un dato que
    vale cero)."""
    ctx = build_mission_context("asset-x", source_id="s", criticality="high", crown_jewel=False)
    result = assess_blast_radius(mission_context=ctx, technical_affected_count=0)
    assert result.mission_blast_radius == "NONE"


# ---------------------------------------------------------------------------
# Clasificación real por criticality/crown_jewel.
# ---------------------------------------------------------------------------


def test_crown_jewel_with_any_technical_impact_is_critical():
    ctx = build_mission_context("asset-x", source_id="s", criticality="low", crown_jewel=True)
    result = assess_blast_radius(mission_context=ctx, technical_affected_count=1)
    assert result.mission_blast_radius == "CRITICAL"


def test_high_criticality_non_crown_jewel_is_high():
    ctx = build_mission_context("asset-x", source_id="s", criticality="high", crown_jewel=False)
    result = assess_blast_radius(mission_context=ctx, technical_affected_count=1)
    assert result.mission_blast_radius == "HIGH"


def test_medium_criticality_non_crown_jewel_is_medium():
    ctx = build_mission_context("asset-x", source_id="s", criticality="medium", crown_jewel=False)
    result = assess_blast_radius(mission_context=ctx, technical_affected_count=1)
    assert result.mission_blast_radius == "MEDIUM"


def test_low_criticality_non_crown_jewel_is_low():
    ctx = build_mission_context("asset-x", source_id="s", criticality="low", crown_jewel=False)
    result = assess_blast_radius(mission_context=ctx, technical_affected_count=1)
    assert result.mission_blast_radius == "LOW"


def test_operational_blast_radius_scales_with_technical_count():
    ctx = build_mission_context("asset-x", source_id="s", criticality="low", crown_jewel=False)
    assert assess_blast_radius(mission_context=ctx, technical_affected_count=0).operational_blast_radius == "NONE"
    assert assess_blast_radius(mission_context=ctx, technical_affected_count=2).operational_blast_radius == "LOW"
    assert assess_blast_radius(mission_context=ctx, technical_affected_count=5).operational_blast_radius == "MEDIUM"
    assert assess_blast_radius(mission_context=ctx, technical_affected_count=10).operational_blast_radius == "HIGH"


def test_technical_evidence_refs_are_threaded_through_not_reinvented():
    """K6: 'con evidencia de las rutas utilizadas' -- las refs vienen del
    llamante (graph.blast_radius real), nunca se fabrican aquí."""
    ctx = build_mission_context("asset-x", source_id="s", criticality="high", crown_jewel=False)
    refs = ("networkpolicy/argos-cyber-range/default-deny", "rolebinding/argos-cyber-range/gseg-binding")
    result = assess_blast_radius(mission_context=ctx, technical_affected_count=2, technical_evidence_refs=refs)
    assert result.technical_evidence_refs == refs


def test_technical_evidence_refs_default_to_empty_not_none():
    result = assess_blast_radius(mission_context=None, technical_affected_count=None)
    assert result.technical_evidence_refs == ()


def test_reason_is_always_populated():
    for mc, count in [(None, 1), (build_mission_context("a", source_id="s"), 1), (build_mission_context("a", source_id="s", criticality="low", crown_jewel=False), 1)]:
        result = assess_blast_radius(mission_context=mc, technical_affected_count=count)
        assert result.reason
