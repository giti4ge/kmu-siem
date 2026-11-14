# Testcheckliste Erstinstallation (0.1.0-rc.1)

Stand: 2026-11-15 · Zu dieser Checkliste: [ERSTINSTALLATION.md](ERSTINSTALLATION.md)

**Nutzung:** Abschnitte in Reihenfolge abarbeiten (spätere setzen frühere voraus). Je Punkt ergänzen: ✔ ok · ✘ Fehler (Issue-Nr.) · – nicht anwendbar / nicht getestet. Jede ✘-Zeile wird zu einem Issue mit der ID im Titel (z. B. `T-4.2`). Quellen, die beim Kunden nicht existieren, mit „–“ markieren.

Testsystem: ____________ · Datum: ____________ · Tester: ____________ · Version (Web-UI): ____________

## 1. Installation

| ID | Prüfung | Erwartet | Ergebnis |
|---|---|---|---|
| T-1.1 | `install.sh --preflight` | alle Prüfungen ✔ oder nachvollziehbare ⚠, nichts verändert | |
| T-1.2 | `install.sh` interaktiv bis Ende | Selbsttest ohne Fehler, Zusammenfassung mit URL und Fingerabdruck | |
| T-1.3 | Zweiter Lauf von `install.sh` bzw. `--repair` | ändert nichts bzw. stellt Sollzustand her, Daten bleiben | |
| T-1.4 | SSH als `siemadmin` mit Schlüssel; Benutzer `install` gesperrt | Anmeldung ok, Kennwort-Login aus (nur nach bestätigter Schlüsselprobe) | |
| T-1.5 | Neustart der VM | alle Dienste und Container starten selbst, Web-UI erreichbar | |
| T-1.6 | `/var/log/siem-install.log` | keine Klartext-Kennwörter oder Schlüssel | |
| T-1.7 | Daten-Disk | eingehängt unter `/opt/siem/data`, Größe wie erwartet | |

## 2. Anmeldung, Benutzer, Sicherheit

| ID | Prüfung | Erwartet | Ergebnis |
|---|---|---|---|
| T-2.1 | Zertifikat im Browser | Fingerabdruck stimmt mit Installationsausgabe überein | |
| T-2.2 | Anmeldung `admin`, MFA-Einrichtung (TOTP) | QR-Code, Code wird akzeptiert, Pflicht für Admin | |
| T-2.3 | Falsches Kennwort mehrfach | Sperre bzw. Verzögerung, Eintrag im Audit-Log | |
| T-2.4 | Benutzer je Rolle anlegen (Analyst, Auditor, Management) | Menüs und Rechte passen zur Rolle (kein Zugriff auf Fremdes) | |
| T-2.5 | Audit-Log | Anmeldungen und Änderungen sichtbar, Kette „gültig“ | |
| T-2.6 | MFA-Notfall-Reset per CLI | funktioniert, wird protokolliert | |
| T-2.7 | Tiefenanalyse (Dashboards) aus dem Web-UI | Anmeldung ohne zweites Login, Indizes sichtbar | |

## 3. Einrichtung und Betrieb

| ID | Prüfung | Erwartet | Ergebnis |
|---|---|---|---|
| T-3.1 | Dashboard: Ampel, Prüfliste | alle Bereiche grün oder erklärbar | |
| T-3.2 | Benachrichtigung: Testmail | Mail kommt an | |
| T-3.3 | Benachrichtigung: Teams-Test | Karte kommt an | |
| T-3.4 | Zeit (NTP) | Abweichung < 1 s | |
| T-3.5 | Firewall: Freigaben einschränken, anwenden, **bestätigen** | Regeln aktiv, UI bleibt erreichbar | |
| T-3.6 | Firewall: anwenden, **nicht bestätigen** | nach 60 s automatisch zurückgesetzt | |
| T-3.7 | Update-Prüfung (Kanal beta/stable) | meldet Stand ohne Fehler | |
| T-3.8 | Wartung: Plattenwächter, Sicherung der Konfigurationsdatenbank, Integritätsprüfung | läuft, Ergebnis nachvollziehbar | |
| T-3.9 | Diagnosepaket herunterladen | Archiv ohne Kennwörter, Schlüssel, Tokens, Ereignisinhalte (Stichprobe `grep`) | |
| T-3.10 | Support-Zugang aktivieren (Schlüssel, Quell-IP, Dauer) und wieder sperren | nur Diagnosebefehle, läuft ab, Audit-Eintrag, Alarm solange aktiv | |
| T-3.11 | System-Protokoll | keine unerklärten Fehler | |

## 4. Quellen anbinden

Für jede vorhandene Quelle: Anbindung durchführen, Ereignisse erzeugen, in der Tiefenanalyse prüfen (Zeit, Quelle, Felder vollständig). Fehlerhaft erkannte oder fehlende Felder als Parser-Issue mit Probe melden.

| ID | Quelle | Prüfung | Erwartet | Ergebnis |
|---|---|---|---|---|
| T-4.1 | Geräteliste | Gerät anlegen, Typ wählen | Eintrag wirkt nach Neuladen (Vector) | |
| T-4.2 | FortiGate Syslog | Traffic, VPN-Anmeldung, Admin-Login, Konfigänderung erzeugen | Ereignisse korrekt geparst, Kategorie `firewall` | |
| T-4.3 | FortiGate-API (ARP/DHCP) | Token eintragen, Verbindung prüfen | Asset-Center zeigt IP+Hostname je MAC | |
| T-4.4 | FortiGate-Snapshot | Sicherung auslösen, später Änderung → Diff | Diff zeigt die Änderung | |
| T-4.5 | ArubaOS-Switch / Instant On / FS S3900 Syslog | Port up/down, Login, Konfigänderung | Ereignisse korrekt, Typ erkannt | |
| T-4.6 | SNMP-Traps | Trap senden (v2c/v3) | erscheint als `port-up`/`port-down` o. Ä. | |
| T-4.7 | SNMP-Poller | Abfrageziel anlegen | Status, Schnittstellen, Erreichbarkeit; Gerät aus → `device-unreachable` | |
| T-4.8 | Port-Matrix, FDB, LLDP | Seite öffnen | Ports/MACs/Nachbarn plausibel, Uplinks erkennbar | |
| T-4.9 | Asset-Center | neues Endgerät anstecken | erscheint als „neu“ mit Switch/Port/VLAN | |
| T-4.10 | Windows: Skript, GPO, OpenWEC | Onboarding durchführen (DC, Exchange, Member-Server) | Server erscheinen ohne Handarbeit; Anmeldungen (4624/4625) geparst | |
| T-4.11 | Windows: Change-Timeline | AD-Gruppe ändern, Attribut ändern, GPO ändern | Timeline zeigt wer/wann/alt→neu | |
| T-4.12 | Windows: Audit-Policy-Check | Skript ausführen, JSON hochladen | Abweichungen gemeldet | |
| T-4.13 | Linux-Onboarding | Skript auf Debian/RHEL, `ssh`-Login, `sudo` | Ereignisse über Syslog-TLS, auditd-Regeln aktiv | |
| T-4.14 | Sophos Central | Zugangsdaten, Verbindungstest | Data-Lake oder automatischer Fallback; Ereignisse sichtbar | |
| T-4.15 | IKARUS | Syslog senden | Funde mit Bedrohung/Aktion geparst | |
| T-4.16 | Synology, iDRAC, UniFi | Syslog senden | Kategorie `infra`/`network`, Hardwarefehler markiert | |
| T-4.17 | Unbekannte Quelle | Syslog von nicht eingetragener IP | Eintrag unter *Nicht erkannte Quellen*, Freigabe/Ignorieren geht | |
| T-4.18 | Rückwirkende Verarbeitung | Quelle freigeben | gepufferte Ereignisse werden nachträglich geparst | |
| T-4.19 | Probe exportieren | Export einer Quelle | keine Klartext-IPs/Hostnamen/Benutzer (Stichprobe) | |
| T-4.20 | Discovery & MIB | Scan eines Netzes; MIB importieren | Geräte gefunden; MIB-Namen werden aufgelöst | |
| T-4.21 | Parser-Editor | eigene Regel anlegen, Beispielzeile testen | Regel greift, Vector läuft weiter | |

## 5. Erkennung und Alarmierung

| ID | Prüfung | Erwartet | Ergebnis |
|---|---|---|---|
| T-5.1 | Mehrere fehlgeschlagene Anmeldungen (Windows/SSH/FortiGate) | Alarm entsteht, Schwellwert wirkt | |
| T-5.2 | Weitere Regeln je vorhandener Quelle (Admin-Gruppe geändert, Log gelöscht, Port-Flapping, neues Gerät, Malware-Fund …) | Alarm mit MITRE-Zuordnung | |
| T-5.3 | Alarm in Mail und Teams | Zustellung, Link ins Web-UI | |
| T-5.4 | Alarmverwaltung (quittieren, schließen, Regel aus/an, Schwellwert) | Zustand bleibt, Audit-Eintrag | |
| T-5.5 | Fehlalarme über 48 h | Liste der lauten Regeln notieren | |
| T-5.6 | KI-Bridge: Anbieter und Schlüssel eintragen, Alarm erklären | Erklärung kommt, Pseudonymisierung der Daten sichtbar | |
| T-5.7 | KI-Forensik: Vorfallsanalyse | Aussagen mit Beweisbindung (Ereignisverweise) | |
| T-5.8 | Active Response (zuerst manuell) | FortiGate-IP-Sperre setzen und aufheben; automatisch bleibt aus | |

## 6. Reports, Archiv, Fälle, Datenschutz

| ID | Prüfung | Erwartet | Ergebnis |
|---|---|---|---|
| T-6.1 | Report (Zusammenfassung, CSV, Druck/PDF); Rolle Management | Inhalt plausibel, Management sieht nur Reports | |
| T-6.2 | Archiv: nach mehr als 1 h Dateien und Siegel vorhanden | Prüfung „gültig“ | |
| T-6.3 | Manipulationstest: Archivdatei auf Testsystem ändern → Prüfung | Fehler wird benannt und lokalisiert | |
| T-6.4 | RFC-3161-Zeitstempel / Replikation (Verzeichnis oder S3) | täglich Zeitstempel; lokales Löschen erst nach Replikation | |
| T-6.5 | Archiv-Wiederherstellung | `siem-restore-*` mit Ablauf, Siegelprüfung vorab | |
| T-6.6 | Aufbewahrung je Kategorie ändern | Plausibilisierung, Audit-Eintrag (alt → neu) | |
| T-6.7 | Datenschutzmodus ein: Benutzernamen als Pseudonym | Analyst/Auditor/Management sehen Pseudonym, Admin nicht | |
| T-6.8 | Vier-Augen-Prinzip ein: Wiederherstellung, Export, Aufdeckung | zweite Person muss freigeben | |
| T-6.9 | Fall anlegen, Ereignisse als Beweis, abschließen | signiertes Paket, Fallarchiv schreibgeschützt | |
| T-6.10 | Forensik-Export und Prüffunktion | Paket prüfbar, manipuliertes Paket fällt auf | |

## 7. Last und Dauerbetrieb

| ID | Prüfung | Erwartet | Ergebnis |
|---|---|---|---|
| T-7.1 | Realer Betrieb über 7 Tage mit allen Quellen | keine Ausfälle, Plattenverbrauch pro Tag notieren (Prognose in *Aufbewahrung*) | |
| T-7.2 | Lastspitze (z. B. Syslog-Flut, 150 Endpunkte) | Eingangsschutz greift, keine Verluste bei Normalbetrieb, UI bleibt bedienbar | |
| T-7.3 | CPU/RAM/IO im Dauerbetrieb | Werte notieren (Ziel: stabil, kein Swapping) | |
| T-7.4 | VM-Neustart während Betrieb | Ereignisse werden nachgeholt/gepuffert, nichts verloren | |
| T-7.5 | Gesamtes System-Protokoll nach 7 Tagen | Fehler und Warnungen auswerten und melden | |

## 8. Abschluss

- [ ] Alle ✘-Punkte als Issues angelegt, Diagnosepaket angehängt
- [ ] Offene Fragen und Wünsche als Issue (Vorlage *Wunsch*)
- [ ] Notizen zu Ressourcen (T-7.1, T-7.3) an das Betriebstagebuch ([BETRIEB.md](BETRIEB.md))
- [ ] Fazit: Bereit für den Pilotbetrieb? ja / nein, weil: ____________
