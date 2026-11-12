# 1. Einführung

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.4.0)

## 1.1 Zweck der Appliance

Die KMU-SIEM Appliance sammelt die Protokolle aller sicherheitsrelevanten Systeme eines Unternehmens zentral, wertet sie automatisch aus und meldet Auffälligkeiten. Zusätzlich macht sie sichtbar, welche Geräte im Netzwerk aktiv sind und wie die Switches verschaltet sind.

Typische Fragen, die die Appliance beantwortet:

- Wer hat sich wann, wo und mit welchem Ergebnis angemeldet?
- Wer hat Gruppenmitgliedschaften, Gruppenrichtlinien oder Server-Konfigurationen geändert?
- Welche Angriffe hat die Firewall erkannt oder blockiert? Welche Viren hat der Virenschutz gefunden?
- Welches Gerät ist neu im Netzwerk, an welchem Switch-Port hängt es?
- Hat eine Firewall oder ein Domain Controller aufgehört, Protokolle zu senden?
- Sind die Protokolle der letzten Monate vollständig und unverändert (Nachweis gegenüber Revision, Versicherung, Behörde)?

## 1.2 Zielgruppen dieses Handbuchs

| Zielgruppe | Relevante Kapitel |
|---|---|
| **Techniker des Dienstleisters** (Installation, Onboarding, Wartung) | 2, 3, 4, 5, 9, 11, Anhang |
| **Security-Analysten** (tägliche Auswertung, Regelpflege) | 6, 7 |
| **Administratoren beim Kunden** | 6, 9, 10 |
| **Datenschutzbeauftragte, Betriebsrat, Auditoren** | 8, 10 |
| **Geschäftsführung** | 1, Reports (7.4) |

## 1.3 Leistungsumfang

| Bereich | Funktionen |
|---|---|
| Log-Sammlung (agentlos) | FortiGate, ArubaOS-Switch, Aruba Instant On, FS S3900, Windows-Server und -Clients (WEF), Linux (rsyslog/journald), Sophos Central (XDR Data Lake / SIEM-API), Ikarus |
| Erkennung | Sigma-Regeln, Korrelationsregeln, Heartbeat-Überwachung, Threat-Intel-Abgleich, ARP-Guard |
| Alarmierung | E-Mail, MS Teams; Matrix je Kategorie und Severity; Throttling, Digest, Wartungsfenster |
| Reaktion | IP-Sperre auf der FortiGate (manuell oder automatisch) |
| Netzwerk | Switch-Port-Matrix, Asset-Inventar, Discovery-Inbox |
| Compliance | Change-Auditing, File-Integrity-Monitoring, revisionssicheres Archiv, Reports mit NIS2-/ISO-27001-/DSGVO-Bezug |
| Datenschutz | Retention je Kategorie, Datenschutzmodus, optionales Vier-Augen-Prinzip |
| KI (optional) | Erklärung von Alarmen und Anomalie-Digest über externe KI-Dienste mit Anonymisierung |

### Nicht im Leistungsumfang

- Installation von Agenten auf Endgeräten und Auswertung beliebiger Logdateien (z. B. Exchange Message Tracking)
- Überwachung von OT-/Produktionsnetzen (geplant für eine spätere Version)
- Mehrere Standorte über Relay-Instanzen (geplant für eine spätere Version)
- Anmeldung am Web-UI mit AD-Konten, Alarmierung per SMS/Sprachanruf
- Hochverfügbarkeit (Cluster)

## 1.4 Konventionen in diesem Handbuch

| Darstellung | Bedeutung |
|---|---|
| **System → Updates** | Menüpfad im Web-UI |
| `siem-hostd` | Befehl, Dateiname, Dienstname oder Feldname |
| `<appliance-fqdn>` | Platzhalter, durch eigenen Wert ersetzen |
| > **Hinweis:** | Ergänzende Information |
| > **Achtung:** | Möglicher Datenverlust oder Sicherheitsrisiko |
| > **Ab Version x.y.z:** | Versionsabhängiges Verhalten |
| **⚠ Zu verifizieren** | Angabe wird bei Implementierung bzw. am realen Gerät bestätigt |

Beispielwerte im Handbuch: Domäne `firma.local`, Appliance `siem.firma.local` / `10.0.10.50`, Management-Netz `10.0.10.0/24`.

## 1.5 Versionen und Änderungen

- Die installierte Version steht unter **System → Updates** und in der Fußzeile des Web-UI.
- Was sich zwischen Versionen geändert hat, steht im [CHANGELOG](../../CHANGELOG.md) und in den [Release Notes](../release-notes/) der jeweiligen Version (inkl. Upgrade-Hinweisen).
- Wie Versionsnummern zu lesen sind und welche Updates automatisch installiert werden: [VERSIONIERUNG.md](../VERSIONIERUNG.md).
- Das Handbuch einer älteren Version ist im Repository über den Versions-Tag abrufbar.
