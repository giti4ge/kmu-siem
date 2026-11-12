# 7. Erkennung, Alarmierung & Reports

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.3.0)

## 7.1 Regeln

**Regeln & Benachrichtigung → Regeln**

### Regeltypen

| Typ | Beschreibung | Beispiel |
|---|---|---|
| Sigma | Standardisierte Erkennungsregeln der Community, kuratiert | Verdächtige PowerShell-Befehle, Mimikatz-Indikatoren |
| Schwellwert | Anzahl Ereignisse in einem Zeitfenster | > 10 fehlgeschlagene Anmeldungen eines Kontos in 5 min |
| Sequenz | Ereignisse in bestimmter Reihenfolge | Viele Fehlversuche, danach erfolgreiche Anmeldung |
| Heartbeat | Quelle sendet nicht mehr | FortiGate > 15 min ohne Ereignisse |
| Asset | Ereignisse aus ARP-Guard/Discovery | IP/MAC-Konflikt am Gateway |
| Threat-Intel | Treffer auf bekannte schädliche IPs/Domains/Hashes | Verbindung zu Botnet-C2 |
| System | Selbstüberwachung der Appliance | Speicher > 75 %, Archiv-Integrität verletzt |

### Regelzustände

| Zustand | Wirkung |
|---|---|
| **Aktiv** | Alarme werden erzeugt und gemäß Matrix gemeldet |
| **Silent** | Alarme werden erzeugt, aber nicht gemeldet (Testbetrieb) |
| **Aus** | Regel wird nicht ausgeführt |

Neue oder aktualisierte Sigma-Regeln aus dem täglichen Content-Update laufen **7 Tage silent**. Danach werden sie automatisch aktiv, wenn sie weniger als die eingestellte Anzahl Treffer erzeugt haben. Andernfalls warten sie auf manuelle Freigabe. Die Übersicht **Regeln → Zur Freigabe** zeigt die Kandidaten mit Trefferstatistik.

### Ausnahmen

Je Regel: Feld + Bedingung + Wert (z. B. `user.name = svc-backup`), optional mit Ablaufdatum und Begründung. Alle Ausnahmen werden protokolliert.

### Import und Export

- **Export:** einzelne Regeln, Auswahl oder alle, als Paket (ZIP) inklusive Ausnahmen und Matrix-Zuordnung.
- **Import:** Sigma-YAML oder Paket. Vor dem Übernehmen zeigt ein Vergleich neue, geänderte und unveränderte Regeln. Importierte Regeln starten im Zustand *Silent*.

Typischer Einsatz: Ein beim Kunden A bewährter Regelsatz wird auf Kunde B übertragen.

## 7.2 Alarm-Matrix

**Regeln & Benachrichtigung → Alarm-Matrix**

Für jede Kombination aus **Kategorie** (z. B. Anmeldung, Malware, Netzwerk, Verfügbarkeit, Änderungen, System) und **Severity** (Info, Low, Medium, High, Critical) wird festgelegt:

| Einstellung | Optionen |
|---|---|
| Modus | Sofort · Digest (täglich/wöchentlich) · Nur Dashboard |
| Empfänger | Empfängergruppen (E-Mail und/oder Teams) |
| Drosselung | Gleiche Alarme (gleicher Schlüssel, z. B. Regel + Host) werden innerhalb von X Minuten nur einmal gemeldet, danach als Sammelmeldung „N weitere“ |

**Empfohlene Grundeinstellung:**

| Severity | Modus |
|---|---|
| Critical, High | Sofort an IT-Leitung + Dienstleister (E-Mail + Teams) |
| Medium | Täglicher Digest 07:00 |
| Low | Wöchentlicher Digest Montag 07:00 |
| Info | Nur Dashboard |

### Wartungsfenster

**Regeln & Benachrichtigung → Wartungsfenster**: einmalig oder wiederkehrend (z. B. „jeden 2. Dienstag 20:00–02:00“), gültig für Assets, Asset-Gruppen oder Kategorien. Während des Fensters werden Verfügbarkeits-Alarme (Heartbeat, Link-Down) unterdrückt, aber protokolliert.

### Fallback

Schlägt die Zustellung über einen Kanal fehl, wird der Alarm über den anderen Kanal zugestellt und ein Systemalarm erzeugt.

## 7.3 Active Response – IP-Sperre auf der FortiGate

Voraussetzung: FortiGate-API eingerichtet (5.2.2).

### Manuell

Bei Alarmen, Assets und Log-Ereignissen: **IP sperren** → Dauer (1 h, 24 h, 7 Tage, dauerhaft) und Begründung. Die IP wird in die Adressgruppe `SIEM_BLOCK` aufgenommen und nach Ablauf automatisch entfernt.

### Automatisch

Je Regel unter **Reaktion** aktivierbar. Standard: nur **externe** IPs, Dauer 24 h.

### Schutzmechanismen

| Schutz | Beschreibung |
|---|---|
| Schutzliste | Gateway, DCs, DNS-Server, die Appliance, Management-Netze und manuell gepflegte Einträge werden nie gesperrt |
| Limit | Maximal N automatische Sperren pro Stunde, danach nur noch Meldung |
| Ablauf | Jede Sperre hat eine Ablaufzeit (außer manuell „dauerhaft“) |
| Nachvollziehbarkeit | Jede Sperre und Aufhebung wird gemeldet und im Audit-Log erfasst |

**Übersicht:** **Regeln & Benachrichtigung → Aktive Sperren** mit Aufheben-Funktion.

## 7.4 Reports

**Reports**

### Mitgelieferte Vorlagen

| Vorlage | Inhalt | Empfohlener Turnus |
|---|---|---|
| Management-Summary | Sicherheitslage, Trends, offene Risiken, Ampel | monatlich |
| Anmeldungen | Fehlversuche, Sperrungen, Anmeldungen außerhalb der Geschäftszeit, privilegierte Anmeldungen | wöchentlich |
| Konten & Gruppen | Neue/gelöschte Konten, Änderungen privilegierter Gruppen | wöchentlich |
| AD-/GPO-Änderungen | Change-Timeline | wöchentlich |
| Server-Änderungen | Dienste, Tasks, Audit-Policy | wöchentlich |
| File-Integrity | Änderungen an überwachten Pfaden | wöchentlich |
| Firewall | Top-Blocks, Top-Talker, Inter-VLAN, Admin-Logins, Konfigänderungen | wöchentlich |
| VPN | Benutzer, Dauer, Herkunftsland | monatlich |
| AV/EDR | Detections, betroffene Hosts, Isolationen | wöchentlich |
| Assets | Neue/verschwundene Geräte, Konflikte | wöchentlich |
| Verfügbarkeit der Quellen | Heartbeat-Statistik, Lücken | monatlich |
| Archiv-Integritätsnachweis | Prüfergebnis je Kategorie und Zeitraum | monatlich / bei Bedarf |
| Zugriffsprotokoll | Vier-Augen-Anträge, Freigaben, Datenzugriffe | monatlich |
| Compliance-Übersicht | Zuordnung zu NIS2 Art. 21, ISO 27001 A.8.15/A.8.16, DSGVO Art. 32 | quartalsweise |

### Zeitplan und Versand

Je Report: Turnus, Zeitraum, Format (PDF, HTML, CSV), Sprache, Empfängergruppen. Erzeugte Reports bleiben unter **Reports → Historie** abrufbar.

### Eigene Reports

Eine Suche im Log-Explorer mit Aggregation (z. B. „Top 10 Benutzer mit Anmeldefehlern“) kann als **Report-Baustein** gespeichert und in eigene Reports eingefügt werden.

> **Hinweis:** Reports enthalten nur Daten, die der Empfängerrolle zugänglich sind. Bei aktivem Datenschutzmodus werden Personenbezüge pseudonymisiert.

## 7.5 KI-Unterstützung (optional)

**System → KI**

| Einstellung | Beschreibung |
|---|---|
| Anbieter | OpenAI-kompatibel, Anthropic, Azure OpenAI |
| API-Schlüssel, Modell | verschlüsselt gespeichert |
| Funktionen | Alarm-Erklärung (High/Critical), wöchentlicher Anomalie-Digest |
| Tageslimit | maximale Anzahl Anfragen / Token |

**Anonymisierung (immer aktiv):** IP-Adressen, Hostnamen, Benutzernamen, E-Mail-Adressen, Domänen und MAC-Adressen werden vor dem Versand durch Platzhalter ersetzt (z. B. `HOST_07`). Die Antwort wird lokal zurückübersetzt. Der Anomalie-Digest übermittelt nur aggregierte Statistiken, keine Roh-Ereignisse.

> **Achtung:** Vor dem Einschalten prüfen, ob die Nutzung eines externen KI-Dienstes mit dem Datenschutzkonzept des Kunden vereinbar ist (Auftragsverarbeitung, Drittlandübermittlung).
