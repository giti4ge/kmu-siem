# 10. Benutzer, Rollen & Sicherheit

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.4.0)

## 10.1 Benutzer

**System → Benutzer & Rollen → Benutzer**

- Es gibt ausschließlich **lokale Benutzer** der Appliance (keine AD-Anmeldung).
- Kennwortrichtlinie: mindestens 12 Zeichen, Prüfung gegen bekannte, kompromittierte Kennwörter, Sperre nach wiederholten Fehlversuchen mit steigender Wartezeit.
- **TOTP-MFA** (z. B. Microsoft Authenticator, Google Authenticator): Pflicht für System-Admins, für andere Rollen einstellbar.
- Sitzungen laufen nach Inaktivität ab (Standard 30 Minuten).
- Kritische Aktionen (Firewall, Updates, Backup-Wiederherstellung, Benutzerverwaltung) erfordern eine erneute MFA-Bestätigung, wenn die letzte Anmeldung mehr als 5 Minuten zurückliegt.

> **Empfehlung:** Persönliche Konten statt Sammelkonten verwenden, damit das Audit-Log Personen zuordnen kann.

### SSH-Zugang

Der Linux-Benutzer `siemadmin` ist für Wartung per SSH vorgesehen (nur Schlüssel). Weitere SSH-Schlüssel werden unter **System → SSH-Zugang** hinterlegt. Jede SSH-Anmeldung wird im Audit-Log erfasst.

## 10.2 Rollen

### Vordefinierte Rollen

| Rolle | Rechte |
|---|---|
| **System-Admin** | Alles, einschließlich System, Firewall, Updates, Backup, Benutzer |
| **Security-Analyst** | Alarme, Log-Explorer, Dashboards, Assets, Regeln, Reports, Active Response |
| **Auditor** | Nur lesen: Dashboards, Alarme, Reports, Audit-Log |
| **Datenschutz / Betriebsrat** | Freigaben (Vier-Augen), Zugriffsprotokoll, Datenschutz-Reports |
| **Report-Empfänger** | Nur Reports |

### Eigene Rollen

Unter **Rollen → Neue Rolle** werden Rechte je Modul (Lesen / Schreiben / Freigeben) und **Datenbereiche** festgelegt:

| Datenbereich | Beispiel |
|---|---|
| Log-Kategorien | nur `firewall` und `network` |
| Asset-Gruppen | nur Standort A |
| Feld-Maskierung | `user.name` immer maskieren |

Die Rechte gelten überall gleich: Web-UI, API, Reports und OpenSearch Dashboards.

## 10.3 Audit-Log

**System → Audit-Log**

Protokolliert werden alle sicherheitsrelevanten Aktionen: Anmeldungen (erfolgreich und fehlgeschlagen), Konfigurationsänderungen mit altem und neuem Wert, Regel- und Ausnahmeänderungen, Sperren, Exporte, Freigaben, Updates, Backups, SSH-Anmeldungen.

**Manipulationsschutz:** Jeder Eintrag ist mit dem vorherigen verkettet (Hash-Kette) und wird zusätzlich in einen schreibgeschützten Index übertragen. Eine tägliche Prüfung erkennt Veränderungen und löst einen Critical-Alarm aus.

## 10.4 Sicherheitsmerkmale der Appliance

| Bereich | Maßnahme |
|---|---|
| Betriebssystem | Debian 13 minimal, automatische Sicherheitsupdates, Kernel-Härtung, deaktivierte unnötige Module, AppArmor |
| Zugang | SSH nur mit Schlüssel und nur aus freigegebenen Netzen; kein Root-Login |
| Netzwerk | nftables, alles gesperrt außer freigegebenen Diensten und Quellnetzen |
| Integrität | auditd, AIDE (täglich), Härtungsprüfung, `install.sh --repair` |
| Container | ohne Root-Rechte, schreibgeschütztes Dateisystem, minimale Berechtigungen, Images per Prüfsumme festgelegt |
| Web-UI | TLS 1.3, HSTS, Content Security Policy, CSRF-Schutz, Web Application Firewall (OWASP CRS) |
| Geheimnisse | Kennwörter mit Argon2id, Zugangsdaten zu Geräten/APIs verschlüsselt (AES-GCM) |
| Updates | signiert (Ed25519), kein Downgrade, automatischer Rollback |
| Prüfmaßstab | OWASP ASVS 4.0 Level 2 |

## 10.5 Privilegierte Aktionen

Das Web-UI hat keinen direkten Zugriff auf das Betriebssystem. Alle privilegierten Aktionen (Firewall, Netzwerk, Updates, Backup, Neustart) laufen über den Host-Dienst `siem-hostd`, der nur eine feste Liste geprüfter Aktionen ausführt und jede protokolliert.
