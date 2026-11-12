# 8. Datenschutz, Archiv & Compliance

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.3.0)

## 8.1 Aufbewahrung (Retention)

**Datenschutz & Retention → Aufbewahrung**

Für jede Log-Kategorie werden zwei Fristen festgelegt:

| Frist | Bedeutung | Bereich |
|---|---|---|
| **Index** | Wie lange Ereignisse durchsuchbar sind | 7–730 Tage |
| **Archiv** | Wie lange das versiegelte Original aufbewahrt wird (lokal + Langzeitarchiv) | 0–3650 Tage |

Die Anzeige neben jedem Regler zeigt den **prognostizierten Speicherbedarf** auf Basis des gemessenen Tagesvolumens. Werte, die den verfügbaren Speicher überschreiten, werden abgelehnt.

> **Hinweis zum Datenschutz:** Die Fristen sollten im Löschkonzept des Kunden begründet sein (Zweckbindung, Speicherbegrenzung). Typische Werte: Sicherheitsereignisse 180 Tage durchsuchbar, Archiv 1–2 Jahre; Firewall-Traffic 30–90 Tage.

Gelöschte Indizes und Archivdateien werden im Audit-Log protokolliert (Löschnachweis).

## 8.2 Datenschutzmodus (optional)

**Datenschutz & Retention → Datenschutzmodus** – ab Werk **aus**.

Wenn aktiv:

- Benutzernamen und E-Mail-Adressen (optional auch Client-IP-Adressen) werden für die Rollen *Security-Analyst* und *Auditor* als **Pseudonym** angezeigt (z. B. `U-7F3A21`). Das gilt im Web-UI, in Reports und in OpenSearch Dashboards.
- Das Pseudonym ist stabil: Dieselbe Person hat immer dasselbe Pseudonym. Zusammenhänge bleiben dadurch erkennbar.
- **Aufdecken:** Über **Aufdecken beantragen** mit Begründung. Ein zweiter berechtigter Benutzer (z. B. Datenschutzbeauftragter) gibt frei. Antrag, Freigabe und Aufdeckung werden protokolliert.

## 8.3 Vier-Augen-Prinzip (optional)

**Datenschutz & Retention → Vier-Augen-Prinzip** – ab Werk **aus**. Es wird global aktiviert und gilt dann für die ausgewählten Kategorien.

| Geschützte Aktion | Ablauf |
|---|---|
| Einsicht in Roh-Ereignisse geschützter Kategorien | Antrag mit Zweck, Zeitraum und Filter → Freigabe durch zweite Person → zeitlich begrenzter Zugriff (Standard 8 h), nur auf den beantragten Ausschnitt |
| Archiv-Wiederherstellung | Antrag → Freigabe |
| Export von Ereignissen | Antrag → Freigabe |
| Schließen/Löschen von Critical-Alarmen | Bestätigung durch zweite Person |

Ohne Freigabe bleiben sichtbar: Dashboards, Alarme (ohne Roh-Ereignisse), aggregierte Statistiken. So bleibt der Sicherheitsbetrieb arbeitsfähig.

### Notfallzugriff (Break-Glass)

Bei einem akuten Vorfall kann ein Analyst den Zugriff **sofort** öffnen:
- Pflichtbegründung
- sofortige Benachrichtigung aller Freigeber
- Kennzeichnung im Zugriffsprotokoll
- nachträgliche Prüfung erforderlich

### Zugriffsprotokoll

**Datenschutz & Retention → Zugriffsprotokoll** und Report *Zugriffsprotokoll* (7.4): alle Anträge, Freigaben, Ablehnungen, Notfallzugriffe und tatsächlichen Datenzugriffe.

## 8.4 Vorlagen für Datenschutz und Mitbestimmung

**Datenschutz & Retention → Vorlagen** erzeugt aus der aktuellen Konfiguration Dokumente (DOCX/PDF) zur Weiterbearbeitung:

| Vorlage | Inhalt |
|---|---|
| Verzeichnis von Verarbeitungstätigkeiten (Art. 30 DSGVO) | Zweck, Kategorien betroffener Personen und Daten, Empfänger, Fristen, TOMs |
| Löschkonzept | Kategorien, Fristen, Löschverfahren, Nachweis |
| Technische Beschreibung für eine Betriebsvereinbarung | Erhobene Daten, Auswertungen, Zugriffsrechte, Datenschutzmodus, Vier-Augen-Prinzip |

> **Hinweis:** Die Vorlagen ersetzen keine rechtliche Prüfung. In Deutschland ist die Einführung in der Regel nach § 87 Abs. 1 Nr. 6 BetrVG mitbestimmungspflichtig.

## 8.5 Revisionssicheres Archiv

Neben dem durchsuchbaren Index wird jedes Ereignis im **Original** archiviert.

### Funktionsweise

1. Ereignisse werden stündlich je Kategorie in einer komprimierten Datei gesammelt.
2. Jede Datei wird **versiegelt**:
   - SHA-256-Prüfsumme,
   - verkettet mit der Prüfsumme der vorherigen Datei (Hash-Kette: das Entfernen oder Verändern einer Datei fällt auf),
   - digitale Signatur (Ed25519) mit dem Archivschlüssel der Appliance,
   - optional ein **qualifizierter Zeitstempel** (RFC 3161) eines Zeitstempeldienstes.
3. Täglich prüft die Appliance die gesamte Kette. Bei einer Abweichung wird ein **Critical-Alarm** ausgelöst.

### Einstellungen

**Archiv → Einstellungen**: Zeitstempeldienst (URL, optional Zugangsdaten), lokale Aufbewahrung (Standard 30 Tage), Archiv-Retention je Kategorie (8.1).

### Integritätsnachweis

**Archiv → Integrität prüfen**: Zeitraum und Kategorien wählen → Prüfung → **PDF-Nachweis** mit Ergebnis, Prüfsummen, Signatur- und Zeitstempelstatus. Geeignet für Revision, Versicherung oder Behörde.

## 8.6 Langzeitarchiv (extern)

**Archiv → Langzeitarchiv**

| Ziel | Hinweise |
|---|---|
| S3-kompatibel | Empfohlen mit **Object Lock (WORM)**, z. B. MinIO, NetApp StorageGRID, Wasabi |
| SMB/CIFS | Freigabe mit eigenem Dienstkonto, nur Schreib-/Leserechte |
| NFS | NFSv4 empfohlen |
| SFTP | Schlüsselbasierte Anmeldung |

- Replikation täglich (konfigurierbar), Erfolg wird per Prüfsummen-Vergleich bestätigt.
- Lokal gelöscht wird eine Datei erst, wenn die Replikation bestätigt ist **und** die lokale Frist abgelaufen ist.
- Fehlgeschlagene Replikation erzeugt einen Alarm.

## 8.7 Archiv-Wiederherstellung

**Archiv → Wiederherstellen**: Kategorie und Zeitraum wählen → Integritätsprüfung → Einspielen in einen temporären Suchbereich mit Ablaufdatum (Standard 14 Tage). Die wiederhergestellten Daten sind im Log-Explorer mit dem Kennzeichen *Wiederhergestellt* durchsuchbar. Bei aktivem Vier-Augen-Prinzip ist eine Freigabe erforderlich.

## 8.8 Compliance-Bezug

| Anforderung | Unterstützt durch |
|---|---|
| NIS2 Art. 21 (Risikomanagement, Vorfallbehandlung) | Erkennung, Alarmierung, Reports, Archiv |
| ISO/IEC 27001:2022 A.8.15 Protokollierung | Zentrale Sammlung, Integrität, Aufbewahrung |
| ISO/IEC 27001:2022 A.8.16 Überwachung | Regeln, Alarme, Heartbeat |
| DSGVO Art. 32 (Sicherheit der Verarbeitung) | Nachweis von Zugriffen, Integrität |
| DSGVO Art. 5 (Speicherbegrenzung, Zweckbindung) | Retention je Kategorie, Datenschutzmodus, Löschnachweis |

Der Report *Compliance-Übersicht* (7.4) stellt diese Zuordnung mit konkreten Kennzahlen dar.
