# ADR-0007: Host-Netzwerk für Ingest-Container

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Docker umgeht bei veröffentlichten Ports die INPUT-Chain; Firewall-Allowlists hätten für Syslog und WEF nicht gegriffen.

## Entscheidung
Ingest- und Sensor-Container laufen mit `network_mode: host`; es werden keine Ports veröffentlicht.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| DOCKER-USER-Chain pflegen | Container bleiben isoliert | Fehleranfällig, schwer testbar |
| Docker ohne iptables | Volle Kontrolle | Eigenes NAT/Routing nötig |

## Konsequenzen
- nftables-Regeln wirken nachweisbar
- Geringere Netzwerkisolation dieser Container

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitte 3.1 und 4.1
