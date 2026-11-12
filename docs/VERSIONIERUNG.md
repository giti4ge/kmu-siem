# Versionierungs- und Änderungskonzept

Dieses Dokument legt fest, wie Produkt, Content, Spezifikation und Handbuch versioniert werden und wie Versionsunterschiede dokumentiert werden.

---

## 1. Produkt (Appliance-Releases)

### 1.1 Schema: Semantic Versioning `MAJOR.MINOR.PATCH[-PRERELEASE]`

| Teil | Erhöhen wenn … | Beispiel | Update-Verhalten |
|---|---|---|---|
| **MAJOR** | Inkompatible Änderung: Datenmigration ohne Rückweg, geänderte OpenSearch-Hauptversion, Wegfall von Funktionen/Schnittstellen, neue Mindest-Hardware | 1.4.2 → 2.0.0 | **Nie automatisch.** Manuell, mit Upgrade-Hinweisen, Pflicht-Snapshot |
| **MINOR** | Neue Funktionen, abwärtskompatible Schema-Migration, neue Quellen/Parser | 1.4.2 → 1.5.0 | Automatisch im Kanal *Stable* (im Wartungsfenster) |
| **PATCH** | Fehlerbehebung, Sicherheitskorrektur, Parser-Korrektur | 1.4.2 → 1.4.3 | Automatisch im Kanal *Stable* |
| **PRERELEASE** | Vorabversion | 1.5.0-beta.2, 1.5.0-rc.1 | Nur Kanal *Beta* |

- Versionen **< 1.0.0** sind Entwicklungsstände (Phase 0–6). **1.0.0** ist die erste produktiv auslieferbare Version (Abnahme Phase 6).
- Git-Tags: `v1.4.2`. Jedes Tag erzeugt in der CI einen **Release-Entwurf** im Distributions-Repository (Installationspaket, Manifest, Images in GHCR).
- Veröffentlichung: Der Release-Verantwortliche signiert `release.json` lokal mit dem Offline-Schlüssel, lädt `release.json.sig` hoch und veröffentlicht den Entwurf. Erst dann sehen die Appliances die Version.

### 1.1a Abbildung auf GitHub

| Produktbegriff | GitHub |
|---|---|
| Version `X.Y.Z` | Release mit Tag `vX.Y.Z` im Repository `kmu-siem-releases` |
| Kanal `stable` | Releases **ohne** Pre-Release-Markierung |
| Kanal `beta` | zusätzlich Releases **mit** Pre-Release-Markierung (`-beta.N`, `-rc.N`) |
| Content-Paket `YYYY.MM.DD.N` | Release mit Tag `content-YYYY.MM.DD.N` |
| Release Notes | Release-Beschreibung (aus `docs/release-notes/vX.Y.Z.md` erzeugt) |
| Container-Images | `ghcr.io/<owner>/kmu-siem-<dienst>@sha256:…` |

Ein zurückgezogenes Release wird auf GitHub nicht gelöscht, sondern im Manifest der Folgeversion als `revoked` geführt und von den Appliances nicht mehr angeboten.

### 1.2 Release-Kanäle

| Kanal | Inhalt | Zielgruppe |
|---|---|---|
| `stable` | Nur MINOR/PATCH nach mindestens 14 Tagen ohne kritischen Fehler im Beta-Kanal (Ausnahme: Sicherheitskorrekturen) | Alle Kunden |
| `beta` | Prerelease + neue Stable-Versionen sofort | Interne Testsysteme, ausgewählte Kunden |

### 1.3 Kompatibilität & Upgrade-Pfade

- **Direkte Updates** sind innerhalb einer MAJOR-Version von jeder Version auf die neueste erlaubt (Migrationen sind kumulativ).
- **MAJOR-Updates** setzen die letzte MINOR-Version der Vorgänger-MAJOR voraus (z. B. 1.9.x → 2.0.0). `siem-hostd` erzwingt das über `min_from_version` im Manifest.
- **Downgrades** sind ausgeschlossen. Ein Rollback ist nur automatisch unmittelbar nach einem fehlgeschlagenen Update oder manuell auf die vorherige Version über den Pre-Update-Snapshot möglich.
- Jede Version dokumentiert in ihren Release Notes:
  - Komponentenversionen (OpenSearch, Vector, OpenWEC, Debian-Basis, Python, Node),
  - Schema-Version der Config-DB (Alembic-Revision),
  - Version der Index-Templates und ISM-Policies,
  - Version des Sigma-Content-Pakets.

### 1.4 Abkündigungen (Deprecation)

1. Ankündigung im Changelog unter *Deprecated* mit Zielversion der Entfernung.
2. Hinweis im Web-UI (System → Updates) und im System-Protokoll, solange die Funktion verwendet wird.
3. Entfernung frühestens in der nächsten MAJOR-Version.

---

## 2. Spezifikation und Handbuch

| Dokument | Schema | Ablage | Regel |
|---|---|---|---|
| Spezifikation | `MAJOR.MINOR.PATCH` | `docs/spec/SPEC.md` (aktuell), `SPEC-vX.md` (eingefroren) | MAJOR = Architektur-/Scope-Bruch → alte Fassung einfrieren und Vergleichsdokument `SPEC-DIFF-vX-vY.md` erstellen. MINOR = neue Anforderungen. PATCH = Präzisierung |
| Handbuch | Folgt der **Produktversion** | `docs/handbuch/` | Jedes Kapitel trägt im Kopf „Gilt ab Version“. Versionsabhängige Abschnitte werden mit Hinweisblöcken markiert (siehe 2.1) |
| ADR | fortlaufende Nummer | `docs/adr/NNNN-titel.md` | Nie ändern, nur durch neue ADR ersetzen (`Status: ersetzt durch ADR-NNNN`) |
| Release Notes | Produktversion | `docs/release-notes/vX.Y.Z.md` | Pflicht für jede MINOR/MAJOR, empfohlen für PATCH |
| Changelog | Produktversion | `CHANGELOG.md` | Format „Keep a Changelog“, Abschnitt *Unreleased* wird laufend gepflegt |

### 2.1 Versionshinweise im Handbuch

Versionsabhängiges Verhalten wird einheitlich markiert:

> **Ab Version 1.2.0:** Archiv-Replikation zusätzlich auf SFTP.

> **Geändert in Version 2.0.0:** Die Retention wird in Stunden statt Tagen angegeben. Für ältere Versionen siehe Handbuch-Tag `v1.9.0`.

> **Veraltet seit 1.6.0, entfällt in 2.0.0:** …

Das Handbuch einer bestimmten Version ist jederzeit über den Git-Tag abrufbar (`git show v1.4.2:docs/handbuch/…`). Später erzeugt die CI daraus eine versionierte HTML-Dokumentation (GitHub Pages, Versionsauswahl).

---

## 3. Content-Pakete (Kanal 1)

Content wird **unabhängig vom Produkt** versioniert: `YYYY.MM.DD.N` (z. B. `2026.11.13.1`).

| Paket | Inhalt | Kompatibilität |
|---|---|---|
| `sigma` | Kuratiertes Sigma-Set + interne Regeln | Feld `min_app_version` |
| `ioc` | abuse.ch-Feeds | – |
| `oui` | IEEE-OUI-Datenbank | – |
| `parsers` (optional) | Parser-Hotfixes ohne Produkt-Update | Feld `min_app_version` |

Die installierten Content-Versionen sind im UI (System → Updates) und in jedem Support-Export sichtbar.

---

## 4. Ablauf einer Änderung

```
Issue/Anforderung
  → ggf. ADR (bei Architekturentscheidung)
  → ggf. SPEC-Update (MINOR/PATCH) + SPEC-HISTORY
  → Implementierung + Tests + Handbuch-Update im selben Pull Request
  → CHANGELOG „Unreleased“ ergänzen
  → Release: Version festlegen, Release Notes, Tag, signiertes Manifest
```

**Definition of Done** jedes Pull Requests: Tests grün · Handbuch angepasst · Changelog-Eintrag · bei Konfigurations-/Schemaänderung Migrations- und Upgrade-Hinweis.

---

## 5. Git-Konventionen

- Hauptzweig `main` (immer releasefähig), Feature-Branches `feat/…`, `fix/…`, `docs/…`.
- Commit-Nachrichten nach **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `BREAKING CHANGE:` im Footer). Daraus lassen sich Changelog-Entwürfe automatisch erzeugen.
- Tags `vX.Y.Z` nur auf `main`.
- Quellcode: privates Repository `giti4ge/kmu-siem` auf GitHub (`origin`). Distribution: `giti4ge/kmu-siem-releases` (wird mit dem ersten Release angelegt).
- CI auf GitHub Actions. Branch-Schutz für `main` erfordert bei privaten Repositories GitHub Pro (derzeit nicht aktiv). Handbuch später über GitHub Pages.
