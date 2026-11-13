# ADR-0014: Rollback per Backup-Restore

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Alembic-Downgrades sind fehleranfällig; neuere OpenSearch-Indexformate sind nicht abwärtskompatibel.

## Entscheidung
Ein Rollback stellt die Config-DB aus dem Pre-Update-Backup wieder her; vor OpenSearch-Updates wird ein Snapshot erstellt.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Alembic-Downgrade | Kein Backup nötig | Unzuverlässig, nicht für Indizes geeignet |

## Konsequenzen
- Zuverlässiger Rollback
- Änderungen nach dem Update gehen beim Rollback verloren

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.14
