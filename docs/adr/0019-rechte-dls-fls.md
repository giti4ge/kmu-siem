# ADR-0019: Rechte konsistent bis in OpenSearch (DLS/FLS)

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Mit OpenSearch Dashboards gäbe es sonst einen Weg an Rollen, Datenbereichen und Vier-Augen-Prinzip vorbei.

## Entscheidung
Rollen und Datenbereiche werden im Security-Plugin per Document- und Field-Level-Security abgebildet.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Dashboards nur für Admins | Einfach | Analysten ohne Tiefenanalyse |

## Konsequenzen
- Einheitliche Rechte in UI, API, Reports und Dashboards
- Aufwendigere Rollen-Synchronisation

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 5.1
