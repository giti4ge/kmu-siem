# ADR-0022: SNMP-MIB-Import im Web-UI und erweiterbare Geräteklassen

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-13 | Auftraggeber / Entwicklung |

## Kontext
Der Auftraggeber will UniFi (Controller, Switches), Synology NAS und Dell iDRAC anbinden und später Hersteller-MIBs einfach importieren können. Feste OIDs im Code würden bei jedem neuen Gerätetyp Entwicklung erfordern.

## Entscheidung
MIBs werden im Web-UI hochgeladen und serverseitig mit pysmi in einem unprivilegierten, netzwerklosen Unterprozess kompiliert. Das Ergebnis steuert Trap-Namen, Varbind-Auflösung, den OID-Browser fürs Polling und Regelbedingungen. Hersteller-MIBs werden nicht mitgeliefert, nur freie Standard-MIBs. Neue Geräteklassen folgen dem Muster Parser + Fixture-Tests + Profil-YAML.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Feste OIDs im Code | Einfach | Jede neue Geräteklasse braucht eine Programmänderung |
| net-snmp/snmptranslate auf dem Host | Bewährt | Zusätzliche Host-Abhängigkeit, schwerer zu isolieren |
| Hersteller-MIBs mitliefern | Komfort | Lizenzrisiko bei der Weitergabe |

## Konsequenzen
- Neue Geräte ohne Architekturänderung anbindbar
- Zusätzliche Sicherheitsfläche (Upload): Rolle, Limits, Audit, Sandbox
- Kategorie `infra` kommt hinzu (Index-Template, Retention)

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitte 4.6a und 4.6b
