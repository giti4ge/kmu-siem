# ADR-0021: Updates direkt über GitHub Releases + GHCR

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-13 | Auftraggeber / Entwicklung |

## Kontext
Vorgabe des Auftraggebers: Versions- und Funktionsupdates direkt über GitHub. Das Quellcode-Repository ist privat.

## Entscheidung
Releases, Content- und Installationspakete liegen in einem separaten Distributions-Repository, Images in GHCR. Zugriff per read-only Token je Kunde. Vertrauensanker ist die Offline-Ed25519-Signatur; die CI erstellt nur Entwürfe.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Eigener Update-Server | Volle Kontrolle | Betriebsaufwand |
| Releases im Quellcode-Repository | Einfacher | Das Token gäbe Zugriff auf den Quellcode |

## Konsequenzen
- Kein eigener Server nötig
- Abhängigkeit von GitHub; Token-Verwaltung je Kunde

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.14.0
