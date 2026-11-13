# ADR-0020: Auslieferung ausschließlich per install.sh

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-13 | Auftraggeber / Entwicklung |

## Kontext
Vorgabe des Auftraggebers: Installation inklusive Abhängigkeiten und Härtung nur über ein Skript auf einer frischen, schlanken Debian-VM mit SSH; keine VM-Vorlagen.

## Entscheidung
`install.sh` mit Preflight, interaktivem Modus bzw. Antwortdatei, Resume und Repair ist der einzige Installationsweg; kein Packer, keine OVA/VHDX.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| OVA-/VHDX-Vorlagen | Schnelle Bereitstellung | Image-Build, Hypervisor-Abhängigkeit; vom Auftraggeber verworfen |

## Konsequenzen
- Hypervisorunabhängig, Reparatur über denselben Weg
- Ausgangs-VMs variieren → strenger Preflight und CI-Tests auf frischen VMs

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitte 4.1 und 6
