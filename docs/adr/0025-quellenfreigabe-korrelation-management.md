# ADR-0025: Quellenfreigabe, Korrelation und Rolle Management

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-14 | Auftraggeber / Entwicklung |

## Kontext
Neue Quellen sollen nicht ungeprüft in Fach-Indizes gelangen; quellenübergreifende Verfolgung braucht einheitliche Schlüssel; die Geschäftsführung braucht eine reduzierte Sicht.

## Entscheidung
Unbekannte Absender und Assets warten auf Freigabe (nur `siem-unparsed-*`, kurze Aufbewahrung), Ein-Klick-Freigabe mit Nachverarbeitung, Ablehnen sperrt. Korrelationsschlüssel werden bei der Aufnahme normalisiert. Rolle Management mit Standardkennzahlen. Vier-Augen-Freigabe nur über den optionalen Schalter.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Automatische Aufnahme | Bequem | Datenschutz, Rauschen, Missbrauch durch gefälschte Absender |

## Konsequenzen
- Zusätzlicher Zustand im Geräte- und Asset-Modell
- Normalisierung erhöht Aufwand je Parser

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitte 4.12, 4.15, 4.16, [Konzeptrunde 6](../KONZEPTRUNDE-6.md)
