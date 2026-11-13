# ADR-0016: Revisionssicheres Archiv getrennt vom Such-Index

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Abgleich mit iQSol LogApp: manipulationssichere Archivierung ist gefordert. OpenSearch-Indizes sind änderbar und werden nach Ablauf der Retention gelöscht.

## Entscheidung
Zusätzliches Archiv aus stündlichen Dateien mit Hash-Kette, Ed25519-Signatur, optional RFC-3161-Zeitstempel und Replikation auf ein externes, WORM-fähiges Ziel.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Nur OpenSearch read_only | Kein Zusatzaufwand | Kein Integritätsnachweis |

## Konsequenzen
- Beweissicherheit unabhängig vom Index
- Zusätzlicher Speicher (15–25 % der Rohdaten)

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.14a
