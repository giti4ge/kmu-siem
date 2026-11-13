# Entwicklung

Arbeitsweise, Tests und CI für Entwickler. Für Betrieb und Installation siehe [Handbuch](handbuch/README.md).

## 1. Repository-Struktur

```
host/                 Host-Komponenten (install.sh, später siem-hostd, systemd)
  install.sh          Installationsskript (einziger Installationsweg, ADR-0020)
  lib/                Bibliotheken des Installers (je Thema eine Datei)
  siem-hostd/hostd.py privilegierter Host-Dienst (Python, nur Standardbibliothek)
  antworten.env.example
app/                  Anwendung (Container, Control-Plane, Parser, Regeln) – ab Phase 1
tests/
  installer/          Unit-Tests des Installers (bats)
  hostd/              Unit-Tests von siem-hostd (unittest)
  integration/        Integrationstests im Debian-13-Container
  vm/                 Tests auf einer frischen Debian-13-VM (QEMU)
  generators/         Synthetische Log-Generatoren für das Testlabor
tools/                Entwicklungswerkzeuge (z. B. Link-Prüfung)
docs/                 Spezifikation, ADR, Handbuch, Release Notes
.github/workflows/    CI (GitHub Actions)
VERSION               Produktversion (SemVer)
```

## 2. Installer-Architektur (`host/`)

| Datei | Aufgabe |
|---|---|
| `install.sh` | Argumente, Betriebsarten, Ablaufsteuerung |
| `lib/common.sh` | Logging, Ausgabe, Exit-Codes |
| `lib/i18n.sh` | Alle Texte (DE/EN) – keine hartcodierten Meldungen in anderen Dateien |
| `lib/validate.sh` | Eingabevalidierung (rein, ohne Seiteneffekte) |
| `lib/answers.sh` | Antwortdatei (Parser ohne `source`/`eval`), Speichern/Laden, Geheimnisse |
| `lib/state.sh` | Installationszustand für `--resume`/`--repair` |
| `lib/preflight.sh` | Voraussetzungsprüfung: `probe_*` lesen, `pf_*` bewerten |
| `lib/prompts.sh` | Interaktive Abfragen |
| `lib/steps.sh` | Installationsschritte in fester Reihenfolge |

**Regeln:**
- Neue Installationsschritte als Funktion `step_<name>` in einer eigenen Datei `lib/step_<name>.sh`. Jeder Schritt muss **idempotent** sein. Ein zweiter Lauf darf nichts ändern.
- Systemzugriffe in Prüfungen immer über `probe_*`-Funktionen, damit Unit-Tests sie ersetzen können.
- Antwortdateien und Benutzereingaben werden nie ausgewertet (`eval`, `source`, unquotierte Expansion).
- Exit-Codes: 0 OK, 1 Warnungen, 2 Fehler, 3 Schritt nicht implementiert, 64 Aufruffehler.

## 2a. Control-Plane (`app/control-plane/backend`)

FastAPI-Anwendung `siem_api` mit SQLite (WAL) und Alembic-Migrationen.

| Modul | Aufgabe |
|---|---|
| `models.py`, `migrations/` | Datenmodell; jede Änderung braucht eine Migration (Test `test_migrations_match_models`) |
| `security/passwords.py` | Argon2id, Kennwortrichtlinie (≥ 12 Zeichen, zxcvbn-Score ≥ 3, kein Benutzername) |
| `security/totp.py` | TOTP (RFC 6238) mit Schutz gegen Wiederverwendung eines Codes |
| `security/sessions.py` | Serverseitige Sitzungen (Cookie HttpOnly/Secure/SameSite=Strict), CSRF-Token, Anmeldestufen |
| `security/rbac.py` | Berechtigungen `modul:aktion`, vordefinierte Rollen (werden bei jedem Start abgeglichen) |
| `security/crypto.py`, `keys.py` | AES-256-GCM für Geheimnisse; Master- und Audit-Schlüssel in `data/secrets/control-plane` |
| `audit.py` | Audit-Log als HMAC-SHA256-Hash-Kette, Kopf-Datei gegen Abschneiden |
| `deps.py` | `require("modul:aktion")` – jede API-Route außer Anmeldung/Health muss es verwenden |
| `cli.py` | `create-admin` (aus install.sh), `verify-audit` |

**Regeln:**
- Jede neue Route unter `/api/` braucht `Depends(require("modul:aktion"))`. Der Test `test_every_api_route_is_protected` erzwingt das, die Rollen-Matrix wird je Route und Rolle automatisch geprüft.
- Fehler als `{"detail": {"error": "<schlüssel>"}}` – die Übersetzung erfolgt im Frontend. Keine Eingabewerte in Fehlermeldungen.
- Alle zustandsändernden Aktionen schreiben einen Audit-Eintrag (nie Kennwörter oder Geheimnisse).

## 3. Tests

| Ebene | Wo | Läuft auf | Aufruf |
|---|---|---|---|
| Lint | ShellCheck, Ruff, Doku-Links | CI, lokal | siehe unten |
| Unit | `tests/installer/*.bats` | Debian-13-Container (CI), lokal Linux/WSL | `bats tests/installer` |
| Unit | `tests/hostd/test_hostd.py` | überall (Socket-Tests nur Linux) | `python -m unittest discover -s tests/hostd` |
| Unit | `tests/control_plane/` (pytest) | überall (Python ≥ 3.11) | `pip install "./app/control-plane/backend[test]"`, dann `python -m pytest tests/control_plane` |
| Integration | `tests/integration/preflight-container.sh` | Debian-13-Container als root | `bash tests/integration/preflight-container.sh` |
| VM | `tests/vm/run-vm-tests.sh` | Linux mit QEMU (CI: GitHub Actions mit KVM) | `bash tests/vm/run-vm-tests.sh` |
| VM-Varianten | `tests/vm/run-vm-variants.sh` | wie VM, zusätzlich `sshpass` und für `interactive` squid auf Port 3128 | `bash tests/vm/run-vm-variants.sh interactive` bzw. `resume` |

### Lokal unter Windows

- ShellCheck: `pip install --user shellcheck-py`, danach `shellcheck -x -s bash -P host host/install.sh host/lib/*.sh`
- bats: `npx bats@1.11.1 tests/installer` (Git Bash). **Einschränkung:** Unter Windows lassen sich Unix-Dateirechte nicht setzen. Tests, die `0600`/`0700` anlegen, schlagen dort fehl und sind nur unter Linux aussagekräftig.
- Ruff: `pip install --user ruff`, danach `python -m ruff check tests/generators tools`
- Links: `python tools/check_links.py`

Vollständig aussagekräftig sind die Tests nur unter Linux. Maßgeblich ist die CI.

### Testlabor: Log-Generator

```bash
python tests/generators/loggen.py --list
python tests/generators/loggen.py --source all --eps 50 --duration 60 --target 10.0.10.50
```

Die Formate sind aus Herstellerdokumentation **nachgebildet** (keine echten Proben, SPEC R-02).

## 4. CI (GitHub Actions)

| Workflow | Auslöser | Inhalt |
|---|---|---|
| `ci.yml` | Push auf `main`, Pull Requests | Lint, Unit-Tests (Debian 13), Preflight-Integrationstest |
| `vm-test.yml` | Pull Requests/Push mit Änderungen an `host/` oder `tests/vm/`, manuell | Frische Debian-13-VM: Preflight, unbeaufsichtigte Installation, Resume, Repair; parallel die Varianten `interactive` (ohne zweite Disk, Proxy, ohne SSH-Schlüssel) und `resume` (Abbruch in jedem Schritt) |

Der VM-Test nutzt KVM, sofern der Runner es anbietet. Andernfalls läuft er in Software-Emulation (deutlich langsamer).

## 5. Arbeitsablauf

1. Branch von `main`: `feat/…`, `fix/…`, `docs/…`
2. Änderung + Tests + Handbuch + `CHANGELOG.md` (Unreleased) im selben Branch
3. Pull Request. Die CI muss grün sein.
4. Squash-Merge nach `main`

Commit-Nachrichten nach Conventional Commits, siehe [VERSIONIERUNG.md](VERSIONIERUNG.md#5-git-konventionen).
