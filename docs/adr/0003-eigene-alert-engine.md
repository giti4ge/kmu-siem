# ADR-0003: Eine eigene Alert-Engine

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
v1 sah Sigma, ElastAlert2 und OpenSearch Security Analytics parallel vor. Throttling, Alarm-Matrix, Wartungsfenster und Active Response bräuchten dann mehrere Integrationen.

## Entscheidung
Eine Alert-Engine im `worker` führt per pySigma konvertierte Sigma-Regeln und interne Regeln (Schwellwert, Sequenz, Heartbeat, Asset) aus und ist allein für Alarmierung, Drosselung und Reaktion zuständig.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| ElastAlert2 | Etabliert | Eigene Konfigurationswelt, Matrix und Wartungsfenster schwer abbildbar |
| OpenSearch Security Analytics | Integriert | Eingeschränkte Log-Typen, wenig Kontrolle über Benachrichtigungen |

## Konsequenzen
- Eine Stelle für alle Alarmlogik, gut testbar
- Die Engine muss selbst entwickelt und gepflegt werden

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.11
