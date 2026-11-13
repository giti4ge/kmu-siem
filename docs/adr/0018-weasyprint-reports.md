# ADR-0018: Report-Engine mit WeasyPrint

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Reports sollen als PDF ohne Browser-Abhängigkeit erzeugt werden.

## Entscheidung
Jinja2-Vorlagen, PDF per WeasyPrint, zusätzlich HTML und CSV.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Headless Chromium | Volle Web-Darstellung | Großer, sicherheitskritischer Zusatz |

## Konsequenzen
- Schlanke, reproduzierbare PDFs
- Eingeschränkter CSS-Umfang

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.14b
