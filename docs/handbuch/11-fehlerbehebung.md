# 11. Fehlerbehebung

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.3.0)

## 11.1 Erste Schritte

1. **Dashboard → Systemstatus**: Welcher Dienst bzw. welche Quelle ist betroffen?
2. **System → System-Protokoll**: Fehlermeldungen filtern (Dienst, Zeitraum, Schweregrad).
3. Per SSH: `sudo siem-hostd system status`.
4. Bei Bedarf **System → Support-Export**: erzeugt ein Archiv mit Versionen, Konfiguration (ohne Geheimnisse), Diensteprotokollen und Prüfergebnissen für den Dienstleister.

## 11.2 Installation (`install.sh`)

| Symptom | Ursache / Lösung |
|---|---|
| Preflight: „Debian-Version nicht unterstützt“ | Nur Debian 13 (amd64) wird unterstützt. Neu installieren. |
| Preflight: „Ziel nicht erreichbar“ | Internet bzw. Proxy prüfen: `curl -I https://download.docker.com`. Proxy mit `--proxy` oder in der Antwortdatei angeben. |
| Preflight: „Disk nicht leer“ | Die Daten-Disk enthält Partitionen. Im Hypervisor eine neue, leere Disk anhängen oder vorhandene Partitionen bewusst entfernen. |
| Preflight: „Desktop-Umgebung gefunden“ | Debian ohne Desktop neu installieren (3.5). |
| Abbruch während der Installation | Ursache in `/var/log/siem-install.log` (letzter Schritt), beheben, dann `sudo ./install.sh --resume`. |
| Images können nicht geladen werden | Registry über Proxy nicht erreichbar oder TLS-Prüfung durch Proxy (SSL-Inspection). Registry im Proxy ausnehmen oder Proxy-CA mit `--proxy-ca` angeben. |
| Nach Installation kein SSH mehr möglich | Anmeldung als `siemadmin` mit dem hinterlegten Schlüssel. Notfalls über die VM-Konsole anmelden und `sudo /opt/siem/host/install.sh --repair` ausführen. |

## 11.3 Quellen senden keine Ereignisse

| Prüfung | Vorgehen |
|---|---|
| Erreicht der Verkehr die Appliance? | **Quellen → <Quelle> → Diagnose** zeigt eingehende Verbindungen/Pakete der letzten Minuten |
| Firewall der Appliance | Quell-IP in der Allowlist des Dienstes? (**System → Firewall**) |
| Firewall unterwegs | Regel auf der FortiGate / Windows-Firewall für Port 514/6514/5985 |
| TLS (FortiGate, Linux) | Root-CA der Appliance auf dem Sender importiert? Zeit korrekt? |
| Uhrzeit der Quelle | Weicht die Zeit stark ab, erscheinen Ereignisse im falschen Zeitbereich |

### Windows (WEF)

| Symptom | Lösung |
|---|---|
| Server erscheint nicht | Auf dem Server: `gpresult /r` (GPO angewendet?), `winrm qc`, Ereignisprotokoll *Microsoft-Windows-Forwarding/Operational* prüfen |
| Fehler 0x80090322 / Kerberos | SPN `HTTP/siem.firma.local` korrekt und eindeutig (`setspn -Q HTTP/siem.firma.local`)? Keytab aktuell? DNS-Name stimmt mit dem SPN überein? |
| Security-Log fehlt | `NETWORK SERVICE` in *Event Log Readers*? Server nach GPO-Änderung neu gestartet? |
| Nur einzelne Ereignis-IDs fehlen | Audit-Policy unvollständig → **Hardening-Report** (5.4.6) |

### Sophos

| Symptom | Lösung |
|---|---|
| Modus springt auf SIEM-API | Keine XDR-Lizenz oder fehlende Berechtigung der API-Anmeldedaten |
| HTTP 401/403 | Client-Secret abgelaufen oder widerrufen → neue Anmeldedaten |
| HTTP 429 | Abfrage-Limit erreicht. Die Appliance wartet automatisch, keine Aktion nötig. |

## 11.4 Ereignisse werden nicht korrekt erkannt (Unparsed)

**Quellen → Unparsed** zeigt Ereignisse, die kein Parser verarbeiten konnte, gruppiert nach Quelle und Muster.

1. Prüfen, ob die Quelle mit dem richtigen Typ angelegt ist.
2. Beispiel-Ereignisse über **Als Probe exportieren** (Inhalte werden auf Wunsch maskiert) an den Dienstleister übergeben.
3. Korrigierte Parser werden über das Content-Update ausgeliefert, ohne Appliance-Update.

## 11.5 Keine oder zu viele Benachrichtigungen

| Symptom | Lösung |
|---|---|
| Keine E-Mails | **Kanäle → Testmail**; System-Protokoll auf SMTP-Fehler prüfen (TLS, Anmeldung, Relay-Berechtigung) |
| Keine Teams-Nachrichten | Workflow in Teams noch aktiv? URL neu erzeugen und eintragen |
| Zu viele Meldungen | Drosselung in der Alarm-Matrix erhöhen, Ausnahmen anlegen, Regel auf *Silent* stellen |
| Alarm fehlt während Patch-Day | Aktives Wartungsfenster? (gewollt) |

## 11.6 Speicher und Leistung

| Symptom | Lösung |
|---|---|
| Speicher läuft voll | Retention je Kategorie prüfen, große Quellen identifizieren (**Quellen**, Spalte Datenmenge), Disk vergrößern (9.3) |
| Suche langsam | Zeitbereich einschränken, Kategorien filtern; RAM auf 24 GB erhöhen |
| Ereignisse verzögert | **Dashboard → Systemstatus**: Puffer-Füllstand, Verarbeitungsverzögerung; ggf. einzelne Quelle mit extremem Volumen (z. B. Traffic-Logging) reduzieren |

## 11.7 Update fehlgeschlagen

Ein fehlgeschlagenes Update wird automatisch zurückgerollt. Details: **System → Updates → Versionshistorie → Protokoll**. Häufige Ursachen: zu wenig freier Speicher, Registry nicht erreichbar. Nach Behebung erneut starten. Den Support-Export dem Dienstleister übergeben, wenn der Fehler bleibt.
