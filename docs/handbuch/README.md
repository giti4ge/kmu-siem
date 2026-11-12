# Betriebshandbuch – KMU-SIEM Appliance

| Handbuch für Produktversion | Grundlage | Status |
|---|---|---|
| 1.0.0 (geplant) | Spezifikation 2.4.0 | **Soll-Dokumentation** – Entwurf vor Implementierung |

## Inhalt

1. [Einführung](01-einfuehrung.md) – Zweck, Zielgruppen, Konventionen, Versionshinweise
2. [Systemüberblick](02-systemueberblick.md) – Architektur, Komponenten, Datenfluss
3. [Installation](03-installation.md) – VM vorbereiten, Debian installieren, `install.sh` (Preflight, interaktiv, Antwortdatei, Resume, Repair)
4. [Erstkonfiguration](04-erstkonfiguration.md) – Netzwerk, Zeit, Zertifikate, Mail/Teams, Firewall
5. [Quellen anbinden](05-quellen-anbinden.md) – FortiGate, Switches, Windows, Linux, Sophos, Ikarus
6. [Bedienung](06-bedienung.md) – Dashboard, Alarme, Log-Suche, Assets, Port-Matrix, Change-Audit
7. [Erkennung, Alarmierung & Reports](07-erkennung-alarmierung-reports.md)
8. [Datenschutz, Archiv & Compliance](08-datenschutz-archiv-compliance.md)
9. [Betrieb & Wartung](09-betrieb-wartung.md) – Updates, Backup, Speicher, Überwachung
10. [Benutzer, Rollen & Sicherheit](10-benutzer-rollen-sicherheit.md)
11. [Fehlerbehebung](11-fehlerbehebung.md)
- [Anhang](anhang.md) – Ports, Ereignis-IDs, Log-Kategorien, Glossar

## Pflege

- Jedes Kapitel nennt im Kopf, ab welcher Produktversion es gilt.
- Änderungen am Verhalten werden mit Versionshinweisen markiert (siehe [VERSIONIERUNG.md](../VERSIONIERUNG.md#21-versionshinweise-im-handbuch)).
- Handbuch-Änderungen erfolgen im selben Pull Request wie die Code-Änderung.
- **⚠ Zu verifizieren** kennzeichnet Angaben, die bei der Implementierung bzw. am realen Gerät bestätigt werden müssen.
