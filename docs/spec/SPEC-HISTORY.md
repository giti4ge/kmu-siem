# Änderungshistorie der Spezifikation

Versionierung der Spezifikation nach [VERSIONIERUNG.md](../VERSIONIERUNG.md#2-spezifikation-und-handbuch):
**MAJOR** = Architektur-/Scope-Bruch, **MINOR** = neue Funktionen/Anforderungen, **PATCH** = Präzisierung ohne fachliche Änderung.

| Version | Datum | Auslöser | Änderungen | Dokument |
|---|---|---|---|---|
| 1.0.0 | 2026-11-12 | Ausgangskonzept | Erstfassung | [SPEC-v1.md](SPEC-v1.md) |
| 2.0.0 | 2026-11-12 | Technische Prüfung + Kundenentscheidungen (Runde 1 & 2) | Architektur-Korrekturen (Docker/nftables, Sizing, ZSTD, Watermarks), eine Alert-Engine, Hybrid-Log-Explorer, nmap ersetzt, ARP-Guard ohne Port-Mirror, Retention je Kategorie, Datenschutzmodus, Teams, nur externe KI, Active Response, Sophos XDR Data Lake, Kerberos-WEF, ADR-01 – ADR-15 | [SPEC.md](SPEC.md) |
| 2.1.0 | 2026-11-12 | Abgleich mit Referenzprodukt iQSol LogApp | Revisionssicheres Archiv + Langzeitarchiv, Report-Engine mit Compliance-Mapping, Change-Auditing, agentloses FIM, Linux agentlos, Windows-Clients optional, Audit-Policy-Check, Vier-Augen-Prinzip für Events/Alarme/Archiv, granulares Rollenkonzept, Regel-Import/-Export, System-Protokoll, DE/EN, ADR-16 – ADR-19, Abschnitt 8a | [SPEC.md](SPEC.md) |
| 2.2.0 | 2026-11-13 | Kundenentscheidungen (Runde 3) | Vier-Augen-Prinzip optional (Default aus); Kaskadierung und OT als Roadmap (Abschnitt 10) mit Architektur-Vorkehrungen | [SPEC.md](SPEC.md) |
| 2.3.0 | 2026-11-13 | Kundenentscheidung (Runde 4) | Auslieferung ausschließlich per `install.sh` auf frischer Debian-13-VM mit SSH; OVA/VHDX und Packer entfallen; Betriebsarten `--preflight/--unattended/--resume/--repair`; Schutz vor SSH-Aussperren; Daten-Disk per LVM durch das Skript; CI-Installationstests; Einrichtungsassistent im Web-UI statt Konsolen-Assistent; Kategorie `linux` ergänzt; ADR-20, R-10, R-11 | [SPEC.md](SPEC.md) |

| 2.4.0 | 2026-11-13 | Kundenentscheidung (Runde 5) | Versions-, Funktions- und Content-Updates direkt über GitHub Releases + GHCR (Abschnitt 4.14.0); separates Distributions-Repository; Zugangstoken je Kunde; Offline-Signatur bleibt Vertrauensanker (CI erstellt nur Entwürfe); Bootstrap-Installation von GitHub; Auswahl bestimmter Versionen im UI/CLI; ADR-21, R-12, R-13 | [SPEC.md](SPEC.md) |

> **Einstufung 2.3.0 als MINOR:** Die Architektur der Appliance bleibt unverändert, nur der Auslieferungsweg ändert sich. Die Spezifikation war zu diesem Zeitpunkt noch nicht freigegeben.

## Entscheidungen des Auftraggebers (Nachweis)

| Runde | Datum | Entscheidung |
|---|---|---|
| 1 | 2026-11-12 | Betrieb beim Kunden; Mitlieferung im Rahmen der Dienstleistung (kein Verkauf); kein Air-Gap; Datenschutzkonzept optional aktivierbar; Retention je Log-Typ; ArubaOS-Switch + Aruba Instant On; FS S3900; AD-Domäne mit DCs, Exchange und Member-Servern, einfaches Onboarding; Sophos XDR Data Lake primär, Fallback Events/Alerts; keine Beispiel-Logs; kein Port-Mirroring; Log-Explorer-Entscheidung an Entwicklung delegiert |
| 2 | 2026-11-12 | Alarmierung nur E-Mail + MS Teams; Zugriff Dienstleister über SSH/Web-UI; nur lokale Benutzer; nur externe KI-APIs; Active Response manuell + optional automatisch; Exchange Message Tracking nicht notwendig; viele Kunden mit XDR-Lizenz |
| 3 | 2026-11-13 | Funktionen der iQSol LogApp berücksichtigen; Vier-Augen-Prinzip nur optional; Kaskadierung derzeit nicht notwendig; OT-Umgebungen vorhanden, in dieser Version nicht notwendig |
| 4 | 2026-11-13 | Installation inkl. aller Abhängigkeiten und Härtung ausschließlich über das Installationsskript für Debian; Ausgangssituation neue schlanke Debian-VM mit SSH; keine VMware-/Hyper-V-Vorlage mehr. Repository lokal, später GitHub |
| 5 | 2026-11-13 | Repository auf GitHub (`giti4ge/kmu-siem`, privat). Versions- und Funktionsupdates auf dem SIEM-Server sollen direkt über GitHub erfolgen |
| 6 | 2026-11-13 | Spezifikation 2.4.0 freigegeben, inkl. Trennung Quellcode-/Distributions-Repository mit Token je Kunde; Start der Umsetzung (Phase 0) |
