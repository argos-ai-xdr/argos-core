# soc-adapter

Construye `SOCHandover v1` y lo filtra por TLP (`redact_for_tlp`). Los campos **requeridos** del schema nunca se eliminan (rompería la validación); en `RED` se generalizan (`incident_summary`, descripciones de `timeline`). Los campos **opcionales** (`iocs`, `attack_techniques`, `actions`) se omiten por completo en los niveles más restrictivos según `_OPTIONAL_FIELDS_ALLOWED`.

`redact_for_tlp` nunca muta el payload original: la versión completa sin redactar es la que debe quedar en el evidence store; solo la copia exportada se filtra.
