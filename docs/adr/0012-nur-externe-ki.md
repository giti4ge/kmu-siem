# ADR-0012: Nur externe KI, Anonymisierung verpflichtend

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Ein lokales LLM ist mit 16–24 GB RAM ohne GPU nicht sinnvoll; der Auftraggeber wählte nur externe APIs.

## Entscheidung
KI-Funktionen nutzen ausschließlich externe APIs; ein Anonymizer ersetzt IPs, Hostnamen, Benutzer, E-Mail-Adressen, Domänen und MACs vor dem Versand.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Lokales Ollama | Keine Datenübermittlung | Ressourcen fehlen |

## Konsequenzen
- Datenschutzprüfung beim Kunden nötig
- KI bleibt optional und standardmäßig aus

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.12
