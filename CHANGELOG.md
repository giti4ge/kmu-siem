# Changelog

Alle relevanten Änderungen am Produkt werden in dieser Datei dokumentiert.

Format: [Keep a Changelog](https://keepachangelog.com/de/1.1.0/) · Versionierung: [Semantic Versioning](https://semver.org/lang/de/) – Details in [docs/VERSIONIERUNG.md](docs/VERSIONIERUNG.md).

Kategorien: **Added** (neu) · **Changed** (geändert) · **Deprecated** (abgekündigt) · **Removed** (entfernt) · **Fixed** (behoben) · **Security** (Sicherheit).

---

## [Unreleased]

### Added
- **Phase 1.4:** `install.sh --repair` stellt den Sollzustand mit den gespeicherten Angaben wieder her (alle Schritte idempotent, ohne Fragen, ohne Datenänderung). Selbsttest ergänzt um Integritätsüberwachung (AIDE-Datenbank mit Ausnahmen für veränderliche Daten, tägliche Prüfung, rkhunter) und Lynis-Härtungsindex (Zielwert ≥ 80, Warnung bei Unterschreitung). Ergänzende Härtung: Core-Dumps aus, Anmelde-Banner, `UMASK 027` und Kennwort-Alterung für neue Konten, restriktive cron-/SSH-Rechte, zusätzliche sysctl-Werte, SSH `MaxSessions 2`/`Compression no`, Prozess-Accounting, sysstat, libpam-tmpdir.
- VM-Test 10: AIDE, rkhunter, Lynis ≥ 80, Härtung; `--repair` nach Manipulation (SSH-Drop-in, Modulsperren, sysctl, login.defs, gestoppter Container) ohne Datenverlust.
- **Phase 1.3:** Anwendungs-Stack (OpenSearch 3.9.0, Vector 0.61.0, nginx + ModSecurity + OWASP CRS 4.25 LTS; Images per Digest). Installationsschritte `app` (Bundle, Verzeichnisse je Container-Benutzer, Geheimnisse, interne PKI mit Root-CA, Heap ¼ RAM, Start, Index-Templates und ISM-Richtlinien für 11 Kategorien mit zstd) und `selftest` (Syslog TCP/UDP/TLS Ende-zu-Ende < 10 s, Proxy mit TLS 1.3 und Sicherheits-Headern). Die Installation läuft damit vollständig durch.
- Vector-Pipeline: Syslog → generische ECS-Normalisierung → OpenSearch mit 10-GB-Disk-Puffer.
- CI-Job „Anwendungskonfiguration“ (Vector validate, Compose, nginx -t mit den festgeschriebenen Images).
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
- Firewall: 443→8443, 514→10514, 162→10162 per nftables-Umleitung; interne Ports nur für umgeleiteten Verkehr. Preflight prüft zusätzlich die internen Ports.
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
