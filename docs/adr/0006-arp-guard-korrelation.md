# ADR-0006: ARP-Guard mit Switch-FDB- und FortiGate-Korrelation

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Port-Mirroring ist beim Kunden nicht möglich. Am VLAN-Trunk sind nur Broadcasts sichtbar; ARP-Spoofing per Unicast bleibt passiv unsichtbar.

## Entscheidung
Die Spoofing-Erkennung kombiniert passive Broadcasts mit Switch-MAC-Tabellen (SNMP) und der ARP-Tabelle bzw. den DHCP-Leases der FortiGate (API).

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Nur passiv | Einfach | Spoofing nicht zuverlässig erkennbar |
| Agent auf dem Gateway | Vollständige Sicht | Nicht möglich bzw. nicht gewünscht |

## Konsequenzen
- Erkennung mit Verzögerung des Abfrageintervalls (≤ 2 min)
- Abhängigkeit von der FortiGate-API

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.10
