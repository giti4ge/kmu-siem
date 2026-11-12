# Changelog

Alle relevanten Änderungen am Produkt werden in dieser Datei dokumentiert.

Format: [Keep a Changelog](https://keepachangelog.com/de/1.1.0/) · Versionierung: [Semantic Versioning](https://semver.org/lang/de/) – Details in [docs/VERSIONIERUNG.md](docs/VERSIONIERUNG.md).

Kategorien: **Added** (neu) · **Changed** (geändert) · **Deprecated** (abgekündigt) · **Removed** (entfernt) · **Fixed** (behoben) · **Security** (Sicherheit).

---

## [Unreleased]

### Added
- **Phase 1.2:** `siem-hostd` – privilegierter Host-Dienst mit Aktions-Allowlist (`system.status`, `firewall.show/apply/confirm/rollback`), Unix-Socket mit Gruppenrecht, Audit-Log, Kommandozeile `siem-hostd`. Firewall-Änderungen mit Dead-Man's-Switch (60 s, Token-Bestätigung, Rücknahme auch nach Neustart des Dienstes). Installationsschritt `hostd`.
- **Phase 1.1:** Installationsschritte `base` (Proxy/CA für apt, Systemaktualisierung, Abhängigkeiten, Kopie nach /opt/siem/host), `datadisk` (LVM `siem/data`, ext4, `nodev,nosuid,noexec`, Verzeichnisstruktur), `hardening` (sysctl, Modulsperren, Benutzer `siemadmin`, SSH-Härtung mit Schutz vor Aussperren, auditd-Regeln, chrony, unattended-upgrades), `docker` (offizielles Repository mit Prüfung des GPG-Fingerabdrucks, gehärtete Daemon-Konfiguration, Proxy) und `firewall` (nftables-Tabelle `inet siem` mit Quell-Freigaben je Dienst, Docker-verträglich).
- Antwortschlüssel `SIEM_SSH_PASSWORD_AUTH`.
- VM-Test: vollständige Host-Installation, SSH-Zugang, Firewall-Wirksamkeit, Idempotenz, Preflight nach Teilinstallation.
- **Phase 0:** Installer-Grundgerüst `host/install.sh` mit Preflight (Debian 13, Ressourcen, Daten-Disk, Netzwerk, DNS, Zeit, Internet-Ziele inkl. GitHub/GHCR, Ports, fremde Container-Laufzeiten, Desktop), interaktiven Abfragen, sicherem Antwortdatei-Parser, Zustandsverwaltung für `--resume` und Schrittsteuerung; Texte DE/EN.
- Tests: bats-Unit-Tests, Preflight-Integrationstest im Debian-13-Container, VM-Test auf frischer Debian-13-VM (QEMU).
- CI auf GitHub Actions (Lint, Unit, Integration, VM-Test).
- Synthetischer Log-Generator für das Testlabor (`tests/generators/loggen.py`).
- ADR-0001 bis ADR-0021 als Einzeldokumente, Entwicklerdokumentation (`docs/ENTWICKLUNG.md`).
- Projekt-Repository mit Dokumentationsstruktur (`docs/`).
- Master-Spezifikation 2.4.0 inklusive Änderungshistorie und Versionsvergleich zu 1.0.0.
- Versionierungs- und Änderungskonzept.
- Betriebshandbuch mit 11 Kapiteln und Anhang (Soll-Stand gemäß Spezifikation 2.4.0, wird mit der Implementierung fortgeschrieben).
- Vorlagen für Architecture Decision Records und Release Notes.

### Changed
- Firewall-Regeln werden nur noch von `siem-hostd` erzeugt (Freigaben in `/opt/siem/data/hostd/firewall.json`); der Installer ruft `siem-hostd firewall init` auf.
- Bei jedem Lauf nach der Basis-Installation wird die aktuelle Installer-Version nach `/opt/siem/host` übernommen.
- Spezifikation 4.1 (PATCH): `ip_forward=1` für ausgehenden Container-Verkehr, durch nftables auf die Bridge `br-siem` beschränkt; SSH-Drop-in `00-siem.conf`.
- Auslieferung ausschließlich per `install.sh` auf frischer Debian-13-VM; fertige VM-Vorlagen (`.ova`, `.vhdx`) entfallen (Spezifikation 2.3.0, ADR-20).
- Versions-, Funktions- und Content-Updates direkt über GitHub Releases und GitHub Container Registry; Installation optional per `bootstrap.sh` direkt von GitHub (Spezifikation 2.4.0, ADR-21).
- Spezifikation auf 2.4.0 angehoben.

<!--
Vorlage für ein Release:

## [0.1.0] – JJJJ-MM-TT

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

Komponenten: OpenSearch x.y.z · Vector x.y.z · OpenWEC x.y.z · Debian 13.x
Config-DB-Schema: <alembic-revision> · Index-Templates: vN · Content: YYYY.MM.DD.N
Upgrade-Hinweise: docs/release-notes/v0.1.0.md
-->
