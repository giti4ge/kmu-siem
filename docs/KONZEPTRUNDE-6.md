# Konzeptrunde 6 – Vorbereitung

Stand: 2026-11-14 · Anlass: Ergänzungsliste des Auftraggebers (14.11.2026) · Ziel: Spezifikation 2.6.0 mit neuen Entscheidungen (ADR)

Dieses Dokument ordnet jeden Punkt der Liste dem Ist-Stand und der Roadmap zu und nennt je Themenblock die **offenen Entscheidungen**. Technische Vorschläge sind als Vorgabe formuliert, die der Auftraggeber nur bei Widerspruch ändern muss; fachliche Fragen sind als **Frage** markiert.

## Entscheidungen des Auftraggebers (2026-11-14)

- **Multisite:** Roadmap, **nicht in dieser Version**. Der Auftraggeber hat eine andere Idee, die später besprochen wird; Block A ist damit zurückgestellt (Vorkehrungen aus Spezifikation 10.2 bleiben).
- **KI-Forensik:** wie vorgeschlagen (Block G).
- **Exchange-Logs:** Roadmap, derzeit nicht umsetzen.
- **Poseidon, PA Filesight, Shelly:** Formate werden erst im Betrieb gelernt (Backlog).

**Abschluss der Runde (2026-11-14):**
- **Forensik:** gerichtsverwertbar (ADR-23).
- **KI:** externe Anbieter plus Google Gemini plus eigener Modell-Endpunkt außerhalb der Appliance, kein Modell auf der Appliance (ADR-24).
- **Rolle Management:** ja, Standardkennzahlen.
- **Blöcke B, C, D, H:** Vorgaben übernommen (Freigabe ohne Vier-Augen, Wartung nachts mit E-Mail + Dashboard, Parser-Editor nur Admin/Dienstleister, Skriptverteilung manuell + GPO-Hinweis).
- **Ergebnis:** Spezifikation 2.6.0 (Abschnitte 4.15, 4.16, Roadmap 10.3), ADR-23 – ADR-25. Nächster Schritt: Rückkopplungspaket, dann Phase 5.

## 1. Zuordnung der Punkte

Legende Stand: ✅ vorhanden · 🟡 teilweise · 🔲 offen · ➕ neu (nicht in Spezifikation 2.5.0)

### Betrieb und Bedienung

| Punkt | Stand | Anmerkung |
|---|---|---|
| Fehlererkennung, Bugfixing, Batch-Management („Wie?“) | 🟡 | Selbstüberwachung (5.3) und Updater (Phase 6) vorgesehen; Fehler-Meldeweg, Diagnosepaket und Batch-Verwaltung (Updates/Content/Regeln für mehrere Appliances) fehlen → Block C |
| Welche Datenbank im Backend | ✅ | SQLite (WAL, ADR-0008) für Konfiguration, OpenSearch für Ereignisse; Skalierung bei Multisite siehe Block A |
| Wartungsjobs für Datenbank und Logfiles | 🟡 | ISM-Retention, Docker-Log-Rotation und AIDE vorhanden; es fehlen Backup/Restore der Config-DB, SQLite-Wartung (`VACUUM`/Integritätsprüfung), Snapshot-Verwaltung, Plattenwächter (Spezifikation 4.5) → Phase 6, Zeitplan im UI |
| Neue Syslog-/SNMP-Quellen automatisch erkennen und zuordnen | 🟡 | Auto-Detect an eindeutigen Markern und Bereich „Nicht erkannte Quellen“ vorhanden; Zuordnung per Klick und Lernen der Quelle fehlt → Block B |
| Verarbeitung neuer Quellen muss bestätigt werden (per Dashboard) | ➕ | Freigabe-Workflow („Quarantäne“ für unbekannte Absender) → Block B |
| Eigene Konfigurationsänderungen und Logfiles des SIEM automatisch loggen | 🟡 | Audit-Log (HMAC-Kette) und System-Protokoll vorhanden; Einspeisung in OpenSearch (`audit`/`system`) und Ereignisse der Appliance selbst fehlen → klein, Phase 5 |
| Branchenstandards, Erweiterbarkeit von Regeln und Parsern | 🟡 | Sigma-Import und Muster Parser + Fixture-Test vorgesehen; Parser-Erweiterung im UI (eigene Parser/Regeln ohne Neuinstallation) und ECS/OCSF-Festlegung → Block D |
| Einfache, intuitive Bedienung auch für klassische Administratoren | 🔲 | Querschnitt; Einrichtungsassistent (Phase 6) → Block E |
| Threat-Dashboard (Netzwerkzustand) | ➕ | Dashboard-Seite ist spezifiziert (Ampelstatus, Alerts, EPS); „Threat“-Sicht fehlt → Block E |
| Features anzeigen, Dashboard je Benutzer anpassbar | ➕ | Widget-Layout je Benutzer (Config-DB) → Block E |

### Forensik und KI

| Punkt | Stand | Anmerkung |
|---|---|---|
| Threat suchen und lückenlos verfolgen, unabhängig von der Quelle | 🟡 | Suche und Change-Timeline vorhanden; quellenübergreifende **Korrelation** (Benutzer/Host/IP/Prozess/Sitzung) und Verfolgungsansicht fehlen → Block F |
| Forensik-Export/-Import von Rohdaten | ➕ | Export als signiertes Paket mit Hashliste (Beweiskette); Import zur Anreicherung in eigenen Index → Block F |
| KI-Forensik (Vorfall nachvollziehen, Ursprung, Umfang) | 🟡 | KI-Bridge mit Anonymizer ist spezifiziert (Erklärung je Alert, Wochen-Digest); die **Vorfallsanalyse** mit Beweisbindung fehlt → Block G |
| Pseudonymisierung, kein Halluzinieren, Report | 🟡 | Anonymizer und Audit-Protokoll geplant; **Beweisbindung** (jede Aussage verweist auf Ereignis-IDs, ungeprüfte Aussagen werden verworfen) und Report neu → Block G |

### Anbindung, Deployment und Module

| Punkt | Stand | Anmerkung |
|---|---|---|
| Skript-Bakery (One-Click für DC, Exchange, Member, Clients inkl. Zertifikate) | 🟡 | Windows-Skript je Rolle und Linux-Skript vorhanden; Zertifikate (HTTPS/5986, Syslog-TLS-Clientzertifikate) und ein gemeinsamer Assistent fehlen → Block H |
| OT-Anbindung | 🔲 | Roadmap 10.1, Architektur bereitet vor |
| CrowdStrike | ➕ | analog Sophos (OAuth, Falcon-API; Event Streams/Detections) |
| Exchange-Log-Anbindung | ➕ | In 2.0 bewusst ausgeschlossen („Message Tracking nicht nötig“) – Entscheidung neu bestätigen |
| HP iLO | ➕ | Syslog + SNMP, analog iDRAC (Muster vorhanden) |
| APC-USV | ➕ | SNMP (PowerNet-MIB), Traps und Polling; über MIB-Import (4.6b) |
| Poseidon (Überwachungsdaten) | ➕ | Format klären |
| PA Filesight | ➕ | Format klären (Syslog/Datei?) |
| Shelly | ➕ | HTTP/MQTT (Gen2 Webhook/Notifications), kein Syslog – eigener Collector |
| Erkennung von Konfigurationsänderungen | 🟡 | je Quelle (Windows, FortiGate, Switch) geparst; **einheitliche Änderungsansicht und Konfigurations-Snapshots/Diff** für Geräte fehlen → Block F |
| Modul „supporti“ (Wartungsprobleme, Zertifikate, Domänen SPF/DKIM/MX) | ➕ | eigenes Modul, spätere Version → Block I |
| Modul Threat Intelligence (Vulnerability-/Vendor-Management, Abos) | ➕ | CVE-/Hersteller-Feeds (NVD, CISA KEV, Herstellerseiten), Abgleich mit Assets → Block I |
| Modul Add-ons (GLPI, Checkmk als Docker) | ➕ | Plug-and-Play-Container mit Lebenszyklus; Sicherheits- und Updatefragen → Block I |
| Modul Multisite (Weiterleitung ans SOC, Sammel-Dashboard) | ➕ | ändert Roadmap 10.2 (Kaskadierung) → **Block A, zuerst** |

## 2. Entscheidungsblöcke

### Block A – Multisite (Architekturentscheidung, vor Phase 5)

Ziel des Auftraggebers: je Kunde eine Appliance, im SOC ein Sammeldashboard; Daten verlassen das Haus des Kunden nicht. Variante 2: je Standort eine Appliance, Weiterleitung an eine Zentrale.

**Vorgabe (zur Bestätigung):**
- Zentrale und Standorte sind dasselbe Produkt; ein **Hub-Modus** nimmt Kennzahlen und Alarme der Standorte an (mTLS, Pull oder Push mit Disk-Puffer), kein Rohdatenversand.
- Es gibt drei Weiterleitungsstufen je Standort: *Gesundheit* (Heartbeat, Version, Speicher, Quellenstatus), *Alarme* (Alert-Metadaten) und *Rohdaten* (nur Variante 2, auf Kategorien beschränkbar).
- Das SOC-Sammeldashboard liest nur Kennzahlen und Alarme; die Tiefenanalyse öffnet die Standort-Appliance über einen **ausgehenden Tunnel** (kein Eingangsport beim Kunden), Zugriff nur mit Freigabe des Kunden.
- Mandantentrennung im Hub über ein Mandantenfeld in jedem Dokument und rollenbasierte Sicht.

**Fragen an den Auftraggeber:**
1. Dürfen **Alarmdetails** (z. B. Benutzername, Hostname) zum SOC, oder nur pseudonymisierte Alarme? Das bestimmt, ob die KI-Pseudonymisierung auch hier greift.
2. Soll das SOC auch **steuern** können (Regeln, Updates, Active Response) oder nur lesen?
3. Variante 2: Rohdaten komplett oder nur ausgewählte Kategorien an die Zentrale? Wie viele Standorte (Größenordnung)?

### Block B – Neue Quellen: Erkennung und Freigabe

**Vorgabe:**
- Unbekannte Absender landen im neuen Zustand **„wartet auf Freigabe“** und werden bis zur Freigabe in `siem-unparsed-*` mit kurzer Aufbewahrung gehalten (Datenschutz: nichts in Fach-Indizes).
- Vorschlag je Quelle aus Auto-Detect (Typ, Gerätename aus Hostname, Vertrauen in %) mit **Ein-Klick-Freigabe**; Typ und Name im Dialog änderbar. Freigabe erzeugt den Eintrag in der Geräteliste, protokolliert im Audit-Log und wirkt rückwirkend für gepufferte Ereignisse (Neuverarbeitung).
- Benachrichtigung (Dashboard-Hinweis, optional E-Mail/Teams) bei neuer Quelle; Ablehnen sperrt die Quelle (Drop mit Zähler).
- Dasselbe Verfahren für SNMP-Traps und neue Assets.

**Frage:** Soll die Freigabe das Vier-Augen-Prinzip (optional) unterstützen? Standard: nein.

### Block C – Betrieb: Fehler, Weiterentwicklung, Batch, Datenbank, Wartung

**Vorgabe:**
- **Fehlererkennung:** Selbstüberwachung (5.3) mit Alarmen; zusätzlich ein **Diagnosepaket** (anonymisierte Logs, Versionen, Konfiguration ohne Geheimnisse) per Klick/SSH, das der Dienstleister erhält.
- **Bugfixing/Weiterentwicklung:** Updates über signierte GitHub-Releases (ADR-21), Kanäle *stable/beta*, Rollback, Änderungsprotokoll im UI.
- **Batch-Management** (mehrere Appliances): im Multisite-Hub (Block A) als Aufgabe „Update/Regel-Paket verteilen“ mit Zeitfenster und Staffelung (erst Testkunde); ohne Hub nur je Appliance.
- **Datenbank:** SQLite bleibt für Konfiguration (eine Appliance = ein Schreiber, tägliches Backup per `VACUUM INTO`, Integritätsprüfung); OpenSearch für Ereignisse. Eine Umstellung auf PostgreSQL erst bei Hub-Betrieb mit vielen Mandanten – im Hub vorsorglich PostgreSQL.
- **Wartungsjobs:** wöchentliche Integritätsprüfung, Backup-Rotation, Snapshot-Bereinigung, Log-Rotation, Plattenwächter; Zeitplan und letzter Lauf im UI sichtbar.

**Frage:** Welche Wartungsfenster und welche Alarmierung bei fehlgeschlagenen Wartungsjobs wünschen Sie (Standard: E-Mail + Dashboard-Hinweis)?

### Block D – Standards und Erweiterbarkeit

**Vorgabe:**
- **Datenmodell:** ECS bleibt Standard; **OCSF-Export** als Option. **Regeln:** Sigma (Import/Export), Zuordnung der Felder über ein Mapping. **Bedrohungswissen:** MITRE ATT&CK-Zuordnung je Regel.
- **Eigene Parser:** Parser-Editor im Web-UI (Beispielzeile → Grok-/Regex-Vorschlag → ECS-Zuordnung → Test gegen gespeicherte Proben) mit Versionierung; Benutzerparser laufen in einer begrenzten VRL-Umgebung (keine Dateizugriffe). Standard-Parser kommen über den Content-Kanal.

**Frage:** Sollen Kunden/Dienstleister **eigene Parser selbst bearbeiten** dürfen, oder nur der Hersteller (Sicherheits- und Supportfrage)?

### Block E – Bedienung und Dashboards

**Vorgabe:**
- Rollenbasierte Startseite (Admin: Betrieb und Quellen; Analyst: Alarme und Threat-Sicht; Management: Kennzahlen).
- **Threat-Dashboard:** Netzwerkzustand als Ampel je Bereich (Perimeter, Windows/AD, Server, Netzwerk, Endpunkte), Top-Angreifer-IPs, Anmelde-Anomalien, neue/unbekannte Geräte, Hardware-/Wartungsprobleme, offene Alarme nach Schweregrad.
- **Anpassbar je Benutzer:** Widgets ein-/ausblenden und anordnen; Layout in der Config-DB; Standardlayout je Rolle.
- **Feature-Übersicht:** Katalog „Was kann das System / was ist aktiviert“ mit Direktlinks zur Einrichtung (löst den Wunsch „Anzeige von Features“).
- Leitprinzipien für klassische Administratoren: Assistenten statt Formulare, sprechende Fehlertexte mit Lösungsvorschlag, überall „Warum?/Wie behebe ich das?“.

**Frage:** Gibt es eine Rolle „Management/Geschäftsführung“ mit reduzierter Sicht (Kennzahlen, Report), und welche Kennzahlen gehören dazu?

### Block F – Forensik

**Vorgabe:**
- **Korrelation:** gemeinsame Schlüssel (`user.name/id`, `host.name`, `source/destination.ip`, `process.entity_id`, `session.id`, `siem.case.id`) werden bei der Aufnahme normalisiert (Domänenkonto `user@domain`, Hostname ↔ IP aus DHCP/DNS/ARP). Daraus entsteht eine **Verfolgungsansicht** („Pivot“): von einem Ereignis zu allen zusammengehörigen Ereignissen unabhängig von der Quelle, zeitlich sortiert, mit Auslöser und Folgeereignissen.
- **Fälle (Cases):** Ereignisse, Notizen und Beweise zu einem Vorfall bündeln.
- **Export:** signiertes Paket (JSON-Lines/CSV/Rohdaten), Hashliste, Zeitraum/Filter, Zugriffsprotokoll (Beweiskette); optional verschlüsselt. **Import:** Rohdaten in einen eigenen Index `siem-import-<fall>` zur Anreicherung, unveränderliche Herkunftskennzeichnung, durchsuchbar zusammen mit Live-Daten.
- **Konfigurationsänderungen von Geräten:** täglicher Konfigurations-Snapshot (soweit abrufbar) mit Diff; vereinheitlichte Änderungsansicht.

**Fragen:** Welche forensischen Anforderungen gelten (Gerichtsverwertbarkeit / interne Aufarbeitung)? Wie lange müssen Rohdaten für Vorfälle aufbewahrt werden (Verhältnis zu Retention und Datenschutz)?

### Block G – KI-Forensik (nach Block F)

**Vorgabe (Arbeitsprinzipien gegen Halluzination):**
1. **Beweisbindung:** Die KI erhält nur ausgewählte, bereits korrelierte Ereignisse mit Ereignis-IDs und liefert eine **Zeitlinie als strukturierte Antwort**, in der jede Aussage auf Ereignis-IDs verweist. Eine Aussage ohne gültige ID wird verworfen oder als „Vermutung“ gekennzeichnet.
2. **Prüfschritt lokal:** Die Appliance prüft, dass zitierte Ereignisse existieren und die genannten Felder übereinstimmen, bevor das Ergebnis angezeigt wird.
3. **Zweiter Durchlauf:** Widersprüche zwischen zwei unabhängigen Durchläufen werden markiert; Ergebnisse tragen Konfidenz und Lücken („keine Daten für Zeitraum X“).
4. **Pseudonymisierung** wie in 4.12 (konsistente Platzhalter, Zuordnung lokal, Rückübersetzung lokal); zusätzlich Schwärzung von Freitext (Dateipfade, Kommandozeilen mit Benutzernamen) und ein Testmodus, der die gesendete Anfrage zeigt.
5. **Report:** PDF/CSV mit Zeitlinie, Angriffsvektor (Erstzugriff), betroffenen Systemen und Konten (Umfang), Belegen und Lücken; ausdrücklich als „KI-gestützte Auswertung, zu prüfen“ gekennzeichnet.
6. Szenario „Verschlüsselung“: Erkennung von Massenänderungen (FIM), Löschungen von Schattenkopien/Protokollen (Event 1102/104), Anmeldungen vor dem Ereignis, laterale Bewegung (4624 Typ 3/10), neue Dienste/Tasks und Tool-Nutzung; Rückwärtsverfolgung zum frühesten Auslöser.

**Fragen:** Welche externen KI-Anbieter sind zulässig (Region, Auftragsverarbeitung)? Darf der Anbieter Inhalte nur pseudonymisiert erhalten, oder soll es zusätzlich eine lokale/„private“ Modell-Option geben? Gilt Gerichtsverwertbarkeit für KI-Ergebnisse (vermutlich nein: nur als Hinweis)?

### Block H – Skript-Bakery

**Vorgabe:** Ein Assistent „Server/Client anbinden“ erzeugt je Rolle (DC, Exchange, Member, Client, Linux) ein **signiertes Paket** (Skript + Zertifikate + Prüfsumme) mit One-Click-Download; Zertifikate stammen aus der internen CA (Client-Zertifikate für 5986 und Syslog-TLS), Laufzeit und Widerruf im UI; Paket enthält Rückmeldung (Check-in), sodass das UI „angebunden / wartet“ anzeigt. Skripte laufen nur lesend/konfigurierend, mit `-WhatIf` und Rücknahme-Skript.

**Frage:** Soll die Verteilung der Skripte auch per GPO/Software-Verteilung (z. B. Intune) unterstützt werden?

### Block I – Module (spätere Versionen)

- **supporti:** Prüfungen auf ausstehende Neustarts/Updates (Windows Update-Ereignisse, `needs-restarting`), Zertifikatsablauf (Zertifikatsspeicher/Endpunktprüfung), Anwendungsfehler (Event-ID-Sammlung), Domänenprüfung (SPF/DKIM/DMARC/MX per DNS). **Vorschlag:** eigenständiges Modul mit eigener Seite und Alarmen, ab Version 1.x.
- **Threat Intelligence:** Abos für CVE-/Hersteller-Feeds (NVD, CISA KEV, Hersteller-RSS), Abgleich mit dem Asset-/Softwarebestand, Alarm bei betroffenen Systemen; setzt das Asset-Center mit Softwarestand voraus (Phase 4/5). **Frage:** Welche Hersteller sind bei den Kunden relevant (Fortinet, Microsoft, Aruba, Synology, Dell, Sophos …)?
- **Add-ons (GLPI, Checkmk):** Plug-and-Play-Installation als Container über die Web-UI; je Add-on ein Manifest (Image-Digest, Ports, Volumes, Backup, Update). Sicherheit: eigenes Docker-Netz, Reverse-Proxy-Anbindung, kein Zugriff auf SIEM-Daten. **Frage:** Soll das SIEM Daten mit GLPI/Checkmk austauschen (Assets, Alarme), oder reicht die reine Installation?
- **Neue Anbindungen** (CrowdStrike, Exchange-Logs, HP iLO, APC, Poseidon, PA Filesight, Shelly, OT): je Quelle ein Eintrag im Backlog mit Format, Beispieldaten und Priorität. Quellen mit Syslog/SNMP/REST sind mit dem bekannten Muster umsetzbar; bei **Poseidon, PA Filesight und Shelly** fehlt noch das Format, bei **Exchange** die Entscheidung zu Message Tracking.

## 3. Vorschlag zu Zeitpunkt und Ablauf

| Zeitpunkt | Inhalt | Warum dann |
|---|---|---|
| **Konzeptrunde 6 (eine Sitzung, direkt nach der FortiGate-Anbindung, vor Phase 5)** | Blöcke A, B, F (Korrelationsmodell), E (Rahmen) | Beeinflussen Alert-Engine, Datenmodell und Datenschutz |
| Beginn Phase 5 | Block D, G (Rahmen), C (Wartung/Diagnose) | Detection, KI-Bridge, Selbstüberwachung entstehen dort |
| Ende Phase 5 / vor Phase 6 | Block H, Rest von C | Updater und Einrichtungsassistent |
| Nach Version 1.0 | Block I, neue Anbindungen nach Kundenpriorität | eigene Module, jeweils mit Beispieldaten |

Ergebnis der Runde: Spezifikation 2.6.0 (neue Abschnitte, ADR-23 ff., aktualisierte Phasenplanung) und eine priorisierte Backlog-Liste der neuen Anbindungen.

## 4. Was ich für die Runde brauche

- Antworten auf die **Fragen** in den Blöcken A, B, E, F, G (jeweils kurz; Standardvorschläge gelten bei Schweigen).
- Für die neuen Anbindungen: je Quelle **eine Beispielzeile oder ein Hinweis auf Doku**, sobald vorhanden; Priorität (Kunde, Dringlichkeit).
- Die Information, ob die **Zentrale/das SOC** ein bestehendes Dashboard-System hat, das die Kennzahlen aufnehmen soll.
