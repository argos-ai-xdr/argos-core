# dmz-detector

Detección de anomalías DMZ/egress basada en reglas + baseline autorizado (ARG-018, C-08.UC5): destino no presente en `Baseline.authorized_destinations`, o volumen transferido por encima del umbral esperado (posible exfiltración).

No produce un contrato nuevo: emite `normalizer.RawEvent`, que `normalizer.Normalizer` convierte en `SecurityEvent` real — mismo tratamiento que Wazuh/Falco. Un flujo ya bloqueado (`verdict=DENIED`) también se reporta: un intento de exfiltración contenido sigue siendo señal real, no "sin anomalía" — omitirlo violaría "anomalía crítica golden omitida = 0" (C-08.UC5).
