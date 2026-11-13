# ADR-0002: ECS als einziges Log-Schema

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
v1 nannte ECS und OCSF. Zwei Schemata führen zu doppelten Parsern und unklaren Feldnamen in Regeln.

## Entscheidung
Alle Ereignisse werden auf das Elastic Common Schema (ECS) normalisiert.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| OCSF | Herstellerneutral, wachsende Verbreitung | Weniger Sigma-Mappings, OpenSearch-Ökosystem auf ECS ausgerichtet |
| Beide | Flexibel | Doppelter Aufwand, Inkonsistenz |

## Konsequenzen
- Sigma-Regeln über pySigma-ECS-Pipelines direkt nutzbar
- Eine spätere OCSF-Ausgabe nur per Export-Mapping

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.3
