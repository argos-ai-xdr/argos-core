# recommendation

Produce `Recommendation v1`. `DeterministicFallbackEngine` es real y funcional (ADR-008): un runbook mínimo por severidad, sin red, sin modelo. `LangGraphEngine` es una interfaz documentada que lanza `NotImplementedError` — requiere vLLM desplegado (DEP-06) y el grafo real (ARG-019); no está fingido como "casi listo".

Ningún `RecommendationEngine` (ni el fallback ni el futuro LangGraph) importa un cliente de ejecución de `argos-cyber-tools`: solo produce `Recommendation`, nunca ejecuta (ADR-005/ADR-011).
