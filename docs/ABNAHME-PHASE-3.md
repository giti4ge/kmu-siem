# Abnahme Phase 3 – Ingest & Parser

Stand: 2026-11-14 · Bezug: [Spezifikation 2.5.0, Phase 3](spec/SPEC.md)

## Lieferumfang

| Bereich | Umsetzung |
|---|---|
| Parser | FortiGate, ArubaOS, Aruba Instant On, FS S3900, Linux, Windows (inkl. Change-/FIM-Felder), UniFi, Synology DSM, Dell iDRAC, IKARUS – je mit Fixture-Tests (`app/vector/tests/`, 63 Tests) |
| Routing | Geräteliste (`devices.csv`, API + Web-UI, Neuladen über `siem-hostd`) und Auto-Detect an eindeutigen Markern |
| Onboarding | Windows (OpenWEC, PowerShell-Skript, Keytab, Subscriptions), Linux (rsyslog-TLS, auditd) |
| Sophos | Data Lake primär, automatischer Fallback auf SIEM-API, Modus wählbar |
| Auswertung | „Nicht erkannte Quellen“, Change-Timeline (alt → neu), Audit-Policy-Check, Retention je Kategorie |

## Abnahmekriterien

| Kriterium | Status | Nachweis / Einschränkung |
|---|---|---|
| Je Parser ≥ 95 % der Fixture-Events ECS-konform | **teilweise** | Alle Fixture-Tests bestehen (Vector 0.61.0, lokal). Eine formale ECS-Schema-Validierung fehlt noch; Fixtures sind aus Dokumentation nachgebildet, keine echten Proben (R-02/R-14). |
| Windows-Server erscheint nach Skript + GPO-Update ohne Handarbeit | **offen** | Skript und Subscriptions sind getestet (Syntax, TOML, Keytab-Prüfung); Ende-zu-Ende nur mit echter AD-Umgebung möglich. |
| Sophos-Fallback greift ohne XDR-Lizenz | **erfüllt (simuliert)** | Test mit simulierter 403-Antwort; Tabellen/Felder nicht an echtem Mandanten verifiziert (R-04). |
| Linux-Server liefert nach Snippet SSH-/sudo-Events | **teilweise** | Parser-Tests (sshd, sudo) und Skript-Syntax (`sh -n`) bestehen; echter Lauf auf Debian/RHEL steht aus. |
| Change-Auditing: Gruppe, GPO, AD-Attribut in der Timeline (alt → neu) | **erfüllt** | Parser-Tests und Timeline-Paarungstests. |
| FIM: Änderung erzeugt Event mit Benutzer und Prozess; Massenänderung löst Alarm aus | **teilweise** | Events (4663/4660/4670/5145) geparst; der Alarm folgt mit der Alert-Engine in Phase 5. |
| Audit-Policy-Check meldet falsch konfigurierten Testserver | **erfüllt (simuliert)** | Soll-Ist-Tests mit manipulierten Berichten; Skript nicht auf Windows ausgeführt. |

## Bekannte Lücken und Folgearbeiten

- Die CI konnte für 3.8–3.13 wegen einer GitHub-Billing-Sperre nicht laufen; geprüft wurde lokal (pytest, tsc, i18n, ruff, `vector test`). Nach Behebung `main` pushen und den VM-Test (Installer) nachholen.
- Echte Proben je Hersteller einspielen und die Parser über „Nicht erkannte Quellen“ nachschärfen.
- Sophos: Data-Lake-Tabellen und -Felder an einem echten Mandanten verifizieren; Abruf läuft als API-Thread statt eigenem `integrations`-Container.
- ECS-Schema-Validierung der Fixture-Ausgaben ergänzen (Kriterium 1).
