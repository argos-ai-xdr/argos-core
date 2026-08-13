# correlator

Construye `Incident v1` agrupando `SecurityEvent` por `asset_id` dentro de una ventana temporal (`group_by_asset_and_window`) — regla determinista y explicable, no un modelo de ML.

* **Hecho**: `member_event_ids`, `timeline`, `severity` (máximo de los eventos miembro) se derivan directamente de los eventos.
* **Inferencia**: `attack_techniques` y `confidence` nunca se calculan aquí — `attack_techniques` es un parámetro opcional que debe venir de `argos-contracts-scenarios/mappings/attack/` (todavía no implementado, ver ese README); `confidence` por defecto es `"low"` salvo que el llamador tenga una fuente que la justifique. Inventar una técnica ATT&CK plausible violaría AC08 (grounding CTI, inventados = 0).
