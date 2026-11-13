# ADR-0008: SQLite (WAL) für die Konfiguration

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Die Konfigurationsdatenbank ist klein und wird von wenigen Prozessen genutzt.

## Entscheidung
SQLite im WAL-Modus.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| PostgreSQL | Mehrbenutzerfähig | Zusätzlicher Dienst, Updates, Backup |

## Konsequenzen
- Ein Dienst weniger, einfaches Backup
- Nur ein Schreiber gleichzeitig (ausreichend)

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 3.1
