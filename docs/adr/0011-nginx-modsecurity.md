# ADR-0011: nginx + ModSecurity v3 + OWASP CRS 4

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
v1 ließ Caddy oder nginx offen.

## Entscheidung
nginx mit ModSecurity v3 und CRS 4; Ausnahmen für die Such-Endpunkte.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Caddy + Coraza | Modern, speichersicher | Weniger Erfahrung im CRS-Tuning |

## Konsequenzen
- Etabliert und gut dokumentiert
- CRS-Tuning erforderlich

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 5.1
