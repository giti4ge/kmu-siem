# ADR-0023: Forensik auf Gerichtsverwertbarkeit ausgelegt

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-14 | Auftraggeber / Entwicklung |

## Kontext
Der Auftraggeber verlangt, dass Vorfalldaten gerichtsverwertbar gesichert werden können.

## Entscheidung
Signierte Exportpakete mit SHA-256-Hashliste und RFC-3161-Zeitstempel, lückenlose Zugriffsprotokolle über die Audit-HMAC-Kette, Write-once-Fallarchiv mit eigener Aufbewahrung (Standard 12 Monate ab Fallschluss). Die rechtliche Bewertung im Einzelfall bleibt beim Anwender; KI-Ergebnisse sind nie Beweismittel.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Nur interne Aufarbeitung | Einfacher | Entspricht nicht der Anforderung |
| Zertifizierte Beweissicherung | Höchste Beweiskraft | Nicht mit Open-Source-Appliance erreichbar, Rechtsfrage |

## Konsequenzen
- Zeitstempeldienst nötig (konfigurierbar, Internet im Regelfall vorhanden)
- Aufbewahrung von Fall-Daten steht über der Kategorien-Retention, Abstimmung mit Datenschutzmodus

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitte 4.12, 4.15, 4.16, [Konzeptrunde 6](../KONZEPTRUNDE-6.md)
