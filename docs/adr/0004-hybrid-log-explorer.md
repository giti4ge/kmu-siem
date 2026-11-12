# ADR-0004: Hybrid-Log-Explorer mit OpenSearch Dashboards

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Ein vollständiger Log-Explorer im Eigenbau ist sehr aufwendig; gewünscht ist eine fertige, professionelle Lösung.

## Entscheidung
Eigenes UI für Schnellsuche und Workflows; OpenSearch Dashboards per SSO für die Tiefenanalyse.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Nur eigenes UI | Einheitliche Oberfläche | Hoher Entwicklungsaufwand, Funktionslücken |
| Nur Dashboards | Kein Aufwand | Keine geführten Workflows |

## Konsequenzen
- Rechte müssen bis in OpenSearch durchgesetzt werden (ADR-0019)
- Zwei Oberflächen

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 5.2
