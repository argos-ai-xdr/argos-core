from __future__ import annotations

from temporal_knowledge import TemporalKnowledgeBase, make_fact


def test_query_at_returns_fact_valid_at_that_time():
    kb = TemporalKnowledgeBase()
    fact = make_fact("asset-x", "criticality", "high", source_id="cmam", observed_at="2026-01-01T00:00:00Z", valid_from="2026-01-01T00:00:00Z")
    kb.add_fact(fact)
    assert kb.query_at("asset-x", "criticality", "2026-06-01T00:00:00Z") == fact


def test_query_at_returns_none_before_valid_from():
    kb = TemporalKnowledgeBase()
    fact = make_fact("asset-x", "criticality", "high", source_id="cmam", observed_at="2026-06-01T00:00:00Z", valid_from="2026-06-01T00:00:00Z")
    kb.add_fact(fact)
    assert kb.query_at("asset-x", "criticality", "2026-01-01T00:00:00Z") is None


def test_query_at_returns_none_after_valid_until():
    kb = TemporalKnowledgeBase()
    fact = make_fact(
        "asset-x", "criticality", "high", source_id="cmam",
        observed_at="2026-01-01T00:00:00Z", valid_from="2026-01-01T00:00:00Z", valid_until="2026-03-01T00:00:00Z",
    )
    kb.add_fact(fact)
    assert kb.query_at("asset-x", "criticality", "2026-06-01T00:00:00Z") is None


def test_future_information_leakage_is_zero():
    """El invariante central: un hecho observado DESPUÉS de T nunca se
    devuelve al consultar T, incluso si su valid_from sugiere que ya
    aplicaba entonces -- ARGOS no podía saberlo todavía en T."""
    kb = TemporalKnowledgeBase()
    fact_observed_later = make_fact(
        "asset-x", "criticality", "critical", source_id="incident-response",
        observed_at="2026-08-01T00:00:00Z",  # se descubre en agosto...
        valid_from="2026-01-01T00:00:00Z",  # ...pero dice que ya era así desde enero
    )
    kb.add_fact(fact_observed_later)

    # Consultar un T de marzo (antes de que ARGOS lo supiera) NO debe
    # devolver este hecho, aunque valid_from=enero lo haría "aplicable".
    assert kb.query_at("asset-x", "criticality", "2026-03-01T00:00:00Z") is None
    # Consultar en septiembre (después de observarlo) sí lo devuelve.
    assert kb.query_at("asset-x", "criticality", "2026-09-01T00:00:00Z") == fact_observed_later


def test_supersede_replaces_query_result_after_the_supersession_point():
    kb = TemporalKnowledgeBase()
    old_fact = make_fact("asset-x", "criticality", "medium", source_id="cmam", observed_at="2026-01-01T00:00:00Z", valid_from="2026-01-01T00:00:00Z")
    kb.add_fact(old_fact)
    new_fact = make_fact("asset-x", "criticality", "high", source_id="cmam", observed_at="2026-06-01T00:00:00Z", valid_from="2026-06-01T00:00:00Z")
    kb.add_fact(new_fact)
    kb.supersede(old_fact.fact_id, superseded_at="2026-06-01T00:00:00Z")

    assert kb.query_at("asset-x", "criticality", "2026-03-01T00:00:00Z").value == "medium"
    assert kb.query_at("asset-x", "criticality", "2026-07-01T00:00:00Z").value == "high"


def test_superseded_fact_history_is_preserved_not_deleted():
    kb = TemporalKnowledgeBase()
    old_fact = make_fact("asset-x", "criticality", "medium", source_id="cmam", observed_at="2026-01-01T00:00:00Z", valid_from="2026-01-01T00:00:00Z")
    kb.add_fact(old_fact)
    kb.supersede(old_fact.fact_id, superseded_at="2026-06-01T00:00:00Z")

    history = kb.history_for("asset-x", "criticality")
    assert len(history) == 1
    assert history[0].superseded_at == "2026-06-01T00:00:00Z"
    assert history[0].value == "medium"  # el valor original no se reescribe, solo se marca superseded


def test_query_at_picks_the_most_recent_applicable_fact_among_candidates():
    kb = TemporalKnowledgeBase()
    kb.add_fact(make_fact("asset-x", "criticality", "low", source_id="s1", observed_at="2026-01-01T00:00:00Z", valid_from="2026-01-01T00:00:00Z"))
    kb.add_fact(make_fact("asset-x", "criticality", "high", source_id="s2", observed_at="2026-03-01T00:00:00Z", valid_from="2026-03-01T00:00:00Z"))
    result = kb.query_at("asset-x", "criticality", "2026-06-01T00:00:00Z")
    assert result.value == "high"  # el más reciente de los dos ya vigentes en T


def test_query_at_unknown_entity_returns_none():
    kb = TemporalKnowledgeBase()
    assert kb.query_at("never-seen", "criticality", "2026-01-01T00:00:00Z") is None


def test_add_fact_never_mutates_an_existing_fact():
    kb = TemporalKnowledgeBase()
    fact = make_fact("asset-x", "criticality", "high", source_id="cmam")
    kb.add_fact(fact)
    kb.add_fact(make_fact("asset-x", "criticality", "low", source_id="other"))
    # el primer objeto Python en sí sigue siendo el mismo (frozen, no editado)
    assert fact.value == "high"


def test_temporal_knowledge_base_has_no_delete_method():
    public_methods = {name for name in dir(TemporalKnowledgeBase) if not name.startswith("_")}
    assert public_methods == {"add_fact", "supersede", "all_facts", "query_at", "history_for"}
