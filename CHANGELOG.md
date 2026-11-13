# Changelog

Alle relevanten Änderungen am Produkt werden in dieser Datei dokumentiert.

Format: [Keep a Changelog](https://keepachangelog.com/de/1.1.0/) · Versionierung: [Semantic Versioning](https://semver.org/lang/de/) – Details in [docs/VERSIONIERUNG.md](docs/VERSIONIERUNG.md).

Kategorien: **Added** (neu) · **Changed** (geändert) · **Deprecated** (abgekündigt) · **Removed** (entfernt) · **Fixed** (behoben) · **Security** (Sicherheit).

---

## [Unreleased]

### Added
- **Phase 2.3:** Web-UI (React, TypeScript, Vite, Tailwind, TanStack Query): Anmeldung mit TOTP, verpflichtende 2FA-Einrichtung mit lokal erzeugtem QR-Code, erzwungener Kennwortwechsel, Navigation nach Berechtigungen, Benutzer- und Rollenverwaltung (Berechtigungs-Matrix, Datenbereiche), Audit-Log mit Integritätsprüfung, Sprache DE/EN. CI: Frontend-Build, `tools/check_i18n.py` (keine hartcodierten Texte, DE/EN vollständig, jede API-Fehlermeldung übersetzt), CSP-Prüfung.
- **Phase 2.2:** Control-Plane als Container `siem-api` (uid 2100, read-only, 127.0.0.1:8000) hinter dem Proxy unter `/api/`; Installer legt den Web-Administrator `admin` aus dem Installationskennwort an und löscht das Geheimnis danach (TOTP-Einrichtung beim ersten Login). CLI `reset-mfa` als Notfallzugang per SSH, `create-admin --password-stdin`. Selbsttest prüft `/api/health` über den Proxy. Images aus dem Bundle werden geladen, `pull --policy missing`.
- **Phase 2.1:** Control-Plane-Backend `siem_api` (FastAPI, SQLite/Alembic): lokale Benutzer mit Argon2id und Kennwortrichtlinie, progressive Kontosperre, TOTP-MFA (für System-Admins verpflichtend, Schutz gegen Code-Wiederverwendung), serverseitige Sitzungen mit CSRF-Schutz und Timeouts (30 min Leerlauf, 12 h absolut), Rollen mit granularen Berechtigungen (5 vordefinierte, eigene Rollen mit Datenbereichen), Audit-Log als HMAC-Hash-Kette mit Manipulationserkennung, AES-256-GCM für Geheimnisse, CLI `create-admin`/`verify-audit`. Tests: Rollen-Matrix je Route und Rolle, Manipulation des Audit-Logs (Ändern, Löschen, Abschneiden, Neuberechnen ohne Schlüssel).
- **Phase 1.5:** VM-Test-Varianten für die Abnahme von Phase 1: interaktive Installation ohne zweite Disk, mit Proxy (Nachweis über das Proxy-Protokoll) und ohne SSH-Schlüssel (Kennwort-Anmeldung bleibt aktiv) sowie Abbruch in jedem Installationsschritt mit anschließendem `--resume`. Gemeinsame VM-Testbibliothek `tests/vm/lib.sh`.
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

### Fixed
- Installer: `--resume` nach Abbruch vor oder während der Einrichtung der Daten-Disk scheiterte („Löschung nicht bestätigt“); die Bestätigung wird jetzt gespeichert und eine unvollständige eigene LVM-Anlage fortgesetzt (fremde Volume Groups weiterhin unangetastet).
- Installer: nach einem Abbruch während apt werden unterbrochene dpkg-Vorgänge vor dem nächsten apt-Aufruf automatisch abgeschlossen.

### Changed
- CI: VM-Test-Varianten laufen nur noch auf `main` und manuell (CI-Minuten); neuer Image-Rauchtest der Control-Plane.
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
