# 6. Bedienung

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.3.0)

## 6.1 Oberfläche

- **Navigation links:** Dashboard, Alarme, Log-Explorer, Assets, Switches, Change-Audit & FIM, Reports, Quellen, Regeln & Benachrichtigung, Archiv, Datenschutz & Retention, System. Angezeigt werden nur Module, für die die eigene Rolle berechtigt ist.
- **Kopfzeile:** globale Suche, Zeitbereich, Sprache (DE/EN), Benutzermenü (Kennwort, MFA, Abmelden).
- **Fußzeile:** Produktversion, Content-Version, Systemzeit.

## 6.2 Dashboard

| Bereich | Inhalt |
|---|---|
| Ampel | Gesamtstatus: Quellen (Heartbeat), Dienste, Speicher, Updates, Archiv-Integrität |
| Offene Alarme | Anzahl nach Severity, die neuesten Critical/High |
| Firewall | Blockierte Verbindungen, Top-Quellen/-Ziele, IPS-Ereignisse |
| Ereignisrate | EPS je Quelle (24 h) |
| Assets | Neue Geräte, Konflikte |
| Speicher | Belegung und Prognose |

Ein Klick auf eine Kachel öffnet die gefilterte Detailansicht.

## 6.3 Alarme

### Status-Workflow

`Neu` → `In Bearbeitung` → `Erledigt` oder `False Positive`

- **Zuweisen:** Alarm einem Analysten zuweisen.
- **Kommentar:** Notizen zur Bearbeitung. Diese werden protokolliert.
- **Kontext:** Ereignisse, die den Alarm ausgelöst haben, und ±N Ereignisse derselben Quelle.
- **KI-Erklärung** (falls aktiviert): Klartext-Erklärung und Handlungsempfehlung.
- **Ausnahme anlegen:** Bei Fehlalarmen eine Ausnahme direkt für die Regel anlegen (z. B. bestimmter Benutzer/Host).
- **IP sperren:** Siehe 7.3.

> **Hinweis:** Bei aktivem Vier-Augen-Prinzip müssen Critical-Alarme vor dem Schließen von einer zweiten Person bestätigt werden (siehe 8.3).

## 6.4 Log-Explorer

### Schnellsuche

- Freitext (`fehlgeschlagen admin`) oder Feldsuche (`user.name:mueller AND event.outcome:failure`)
- Zeitbereich, Kategorien, Quellen als Filter
- **Facetten:** Häufigste Werte eines Feldes. Per Klick wird nach dem Wert gefiltert oder er wird ausgeschlossen.
- **Kontext:** Ereignisse vor und nach einem Treffer derselben Quelle
- **Export:** CSV/JSON (protokolliert; bei aktivem Vier-Augen-Prinzip freigabepflichtig)
- **Als Report-Baustein speichern** (siehe 7.4)

### Tiefenanalyse

**In Dashboards öffnen** übergibt die aktuelle Suche an OpenSearch Dashboards (Anmeldung automatisch). Dort stehen Visualisierungen, gespeicherte Suchen und eigene Dashboards zur Verfügung. Es gelten dieselben Rechte und Datenbereiche wie im Web-UI.

## 6.5 Assets & ARP-Guard

### Asset-Liste

Alle bekannten Geräte mit MAC, IP, VLAN, Switch/Port, Hersteller, Hostname, Typ, Kritikalität, *zuerst gesehen*, *zuletzt gesehen* und Datenquelle(n).

### Woher die Daten kommen

| Quelle | Liefert |
|---|---|
| Passives Mithören am VLAN-Trunk | Neue Geräte über ARP-Anfragen, Gratuitous ARP und DHCP |
| Switch-MAC-Tabellen | MAC ↔ Switch-Port ↔ VLAN |
| FortiGate ARP-Tabelle und DHCP-Leases | IP ↔ MAC je VLAN |
| Aktive Discovery | Offene Dienste, Hostnamen, Gerätetyp |

> **Hinweis:** Ohne Port-Spiegelung sieht die Appliance am Trunk nur Broadcasts. Die Erkennung von ARP-Spoofing beruht deshalb zusätzlich auf dem Abgleich der Switch- und FortiGate-Tabellen.

### Discovery-Inbox

Neue, unbekannte Geräte landen hier und werden mit einem Klick eingeordnet: *Firewall, Switch, Server, Client, Drucker, IoT, Ignorieren*. Freigegebene Geräte kommen auf die MAC-Whitelist.

### Alarme

| Alarm | Auslöser |
|---|---|
| Neues Gerät | Unbekannte MAC-Adresse |
| IP/MAC-Konflikt (Spoofing-Verdacht) | IP-Adresse wechselt die MAC-Adresse; höchste Priorität bei Gateway, DCs und Servern |
| MAC-Flapping | MAC-Adresse wechselt häufig den Switch-Port |
| Wiederkehr | Gerät nach mehr als X Tagen wieder aktiv |

### Aktive Discovery

**Assets → Scan-Planung**: Subnetze, Zeitplan und Intensität (nur Erreichbarkeit / Standard-Ports / erweitert). Scans laufen über das Management-Interface oder gekennzeichnete Scan-Interfaces.

> **Achtung:** Aktive Scans können IPS-Alarme auf der FortiGate auslösen. Die Appliance-IP sollte dort als Scanner-Ausnahme hinterlegt werden.

## 6.6 Switch-Port-Matrix

**Switches → <Switch>** zeigt jeden Port als Kachel:

- Link-Status und Geschwindigkeit (10M / 100M / 1G / 10G) farbcodiert
- Untagged- und Tagged-VLANs
- Angeschlossene Geräte (MAC, Hersteller, Asset-Name)
- **Uplinks/Trunks** (per LLDP erkannt) gesondert, mit Anzahl der MACs statt Einzelliste
- Port-Beschreibung (ifAlias)

Ein Klick auf den Port zeigt seine Historie (Link-Wechsel, Geräte, Fehler). Bei Instant-On-Switches werden nur die verfügbaren Informationen angezeigt.

## 6.7 Change-Audit & FIM

### Change-Timeline

Zeigt Änderungen lesbar: **wer – wann – was – alter Wert → neuer Wert**.

| Bereich | Beispiele |
|---|---|
| Active Directory | Objekt angelegt, geändert, verschoben, gelöscht |
| Benutzer & Gruppen | Kennwort zurückgesetzt, Konto gesperrt, Mitgliedschaft in „Domain Admins“ |
| Gruppenrichtlinien | GPO geändert (mit Versionszähler) |
| Server | Dienst installiert, geplanter Task angelegt, Audit-Policy geändert, Ereignisprotokoll gelöscht |
| Exchange | Admin-Befehle mit Parametern |

Filter: Objekt, Benutzer, Server, Zeitraum, Änderungsart. Export als Report.

### File-Integrity-Monitoring

Änderungen an überwachten Pfaden mit Benutzer, Prozess, Aktion und Zeit. Massenänderungen (mehr als N Dateien pro Minute durch einen Benutzer) werden als möglicher Ransomware-Angriff alarmiert.

### Hardening-Report

Ergebnis des Audit-Policy-Checks je Server (siehe 5.4.6).
