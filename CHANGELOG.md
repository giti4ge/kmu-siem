# Changelog

Alle relevanten Änderungen am Produkt werden in dieser Datei dokumentiert.

Format: [Keep a Changelog](https://keepachangelog.com/de/1.1.0/) · Versionierung: [Semantic Versioning](https://semver.org/lang/de/) – Details in [docs/VERSIONIERUNG.md](docs/VERSIONIERUNG.md).

Kategorien: **Added** (neu) · **Changed** (geändert) · **Deprecated** (abgekündigt) · **Removed** (entfernt) · **Fixed** (behoben) · **Security** (Sicherheit).

---

## [Unreleased]

### Added
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
