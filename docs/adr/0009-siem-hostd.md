# ADR-0009: siem-hostd als einzige privilegierte Schnittstelle

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Das Web-UI muss Firewall, Netzwerk, Updates und Backups steuern. Ein Docker-Socket im Container käme Root-Rechten gleich.

## Entscheidung
Ein Host-Daemon mit fester, validierter Aktions-Allowlist über einen Unix-Socket; keine Shell-Interpolation; jede Aktion wird protokolliert.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Docker-Socket im API-Container | Einfach | Vollzugriff bei Kompromittierung |
| sudo-Regeln | Bekannt | Schwer zu validieren, verstreut |

## Konsequenzen
- Klar begrenzte Angriffsfläche
- Jede neue Aktion muss explizit implementiert werden

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 3.3
