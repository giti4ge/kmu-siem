# ADR-0005: Eigener Discovery-Scanner statt nmap

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Die Appliance wird Kunden im Rahmen der Dienstleistung überlassen. Die Nmap Public Source License schränkt die Weitergabe in nicht offenen Produkten ein.

## Entscheidung
Die Asset-Discovery wird als eigener Python-Scanner (ARP-Sweep, ICMP-/TCP-Probes, Banner) umgesetzt.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| nmap | Ausgereift | Lizenzrisiko |
| masscan | Schnell | AGPL, Fokus auf Massenscans |

## Konsequenzen
- Kein Lizenzrisiko
- Geringerer Funktionsumfang als nmap

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.10
