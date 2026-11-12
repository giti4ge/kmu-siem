# ADR-0010: Kerberos über 5985 als WEF-Standard

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Angebunden werden DCs, Exchange und Member-Server in AD-Domänen; die Anbindung soll einfach sein.

## Entscheidung
Standard ist WEF mit Kerberos über HTTP/5985 (Nachrichtenverschlüsselung durch Kerberos); HTTPS/5986 mit Zertifikaten nur optional.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| HTTPS mit Client-Zertifikaten | Auch ohne Domäne nutzbar | Zertifikatsverteilung auf alle Server |

## Konsequenzen
- Einrichtung per Skript und GPO
- Abhängigkeit von DNS und Zeitsynchronisation

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.4
