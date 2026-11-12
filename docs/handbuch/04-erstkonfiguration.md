# 4. Erstkonfiguration

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.3.0)

Empfohlene Reihenfolge: Zeit und Netzwerk → Zertifikate → Benachrichtigung → Firewall → Quellen (Kap. 5) → Regeln/Alarm-Matrix (Kap. 7) → Retention und Datenschutz (Kap. 8) → Backup (Kap. 9).

## 4.1 Netzwerk

**System → Netzwerk**

| Einstellung | Beschreibung |
|---|---|
| Management-Interface | IP, Gateway, DNS. Änderungen werden mit **60-Sekunden-Bestätigung** angewendet (wie Firewall, siehe 4.6) |
| VLAN-Trunk | Interface auswählen und VLAN-IDs eintragen. Die Appliance legt passive Unter-Interfaces **ohne IP-Adresse** an (auch ohne IPv6) |
| Scan-Interfaces (optional) | Für die aktive Discovery in einem VLAN kann ein Unter-Interface **mit IP** konfiguriert werden. Es ist im UI als „aktiv/sichtbar“ gekennzeichnet |
| Proxy | HTTP(S)-Proxy für alle ausgehenden Verbindungen, Ausnahmen (z. B. interne Netze) |

## 4.2 Zeit

**System → Zeit**: NTP-Server (empfohlen: alle DCs der Domäne). Die Appliance meldet eine Abweichung von mehr als 2 Sekunden als Alarm.

> **Hinweis:** Ereignisse werden in UTC gespeichert und in der Zeitzone des Benutzers angezeigt. Exporte enthalten immer UTC mit Zeitzonenangabe.

## 4.3 Hostname und DNS

Der FQDN (`siem.firma.local`) muss vor der Windows-Anbindung im DNS auflösbar sein, weil Kerberos ihn als Dienstnamen verwendet. Eine spätere Änderung erfordert eine neue Keytab (siehe 5.4).

## 4.4 Zertifikate

**System → Zertifikate**

| Option | Wann |
|---|---|
| **Interne Root-CA der Appliance** (Standard) | Die Root-CA muss Browsern, FortiGate (Syslog-TLS) und Linux-Servern bekannt gemacht werden |
| **Eigenes Zertifikat hochladen** (PEM/PKCS#12) | Wenn eine Unternehmens-CA vorhanden ist. Empfohlen für das Web-UI |
| **Zertifikatsanfrage (CSR) erzeugen** | Zertifikat von der Unternehmens-CA ausstellen lassen |

Die Appliance warnt 30 Tage vor Ablauf eines Zertifikats.

## 4.5 Benachrichtigungskanäle

**Regeln & Benachrichtigung → Kanäle**

### E-Mail (SMTP)

| Feld | Beispiel |
|---|---|
| Server / Port | `mail.firma.local` / 587 |
| Verschlüsselung | STARTTLS (empfohlen) oder SMTPS |
| Anmeldung | optional Benutzer/Kennwort |
| Absender | `siem@firma.de` |

Mit **Testmail senden** prüfen. Zustellfehler erscheinen im System-Protokoll und werden über Teams gemeldet, falls konfiguriert.

### Microsoft Teams

Teams-Nachrichten werden über einen **Workflows-Webhook** (Power Automate) zugestellt:

1. In Teams im Zielkanal: **… → Workflows → „Post to a channel when a webhook request is received“** auswählen. **⚠ Zu verifizieren:** Bezeichnung der Vorlage zum Zeitpunkt der Implementierung.
2. Die erzeugte URL kopieren und in der Appliance als Teams-Kanal eintragen.
3. **Testnachricht senden**. Die Nachricht erscheint als Karte mit Severity, Titel, betroffenem System und Link ins Web-UI.

> **Hinweis:** Die Webhook-URL ist ein Geheimnis und wird verschlüsselt gespeichert.

### Empfängergruppen

Unter **Empfänger** werden Gruppen angelegt (z. B. „IT-Leitung“, „Dienstleister-SOC“, „Geschäftsführung“), jeweils mit E-Mail-Adressen, Teams-Kanälen und Sprache (DE/EN). Die Gruppen werden in der Alarm-Matrix und bei Reports verwendet.

## 4.6 Firewall der Appliance

**System → Firewall**

Je Dienst wird festgelegt, welche Quellnetze zugreifen dürfen:

| Dienst | Port | Empfehlung |
|---|---|---|
| SSH | 22/tcp | nur Admin-Arbeitsplätze / Dienstleister-Zugang |
| Web-UI | 443/tcp | nur Admin-Netz |
| Syslog | 514/udp+tcp | nur Switches und sonstige Syslog-Quellen |
| Syslog-TLS | 6514/tcp | FortiGate, Linux-Server |
| Windows-Ereignisweiterleitung | 5985/tcp | nur die angebundenen Windows-Server |
| WEF über HTTPS | 5986/tcp | nur wenn genutzt |
| SNMP-Traps | 162/udp | nur Switches |

**Änderungen anwenden – Dead-Man's-Switch:**

1. **Anwenden** klicken. Die neuen Regeln sind sofort aktiv, ein 60-Sekunden-Countdown startet.
2. Ist das Web-UI weiter erreichbar: **Bestätigen** klicken.
3. Erfolgt keine Bestätigung (z. B. weil man sich ausgesperrt hat), stellt die Appliance automatisch die vorherigen Regeln wieder her.

> **Achtung:** Nach der Installation sind alle privaten Netze (RFC 1918) zugelassen. Die Einschränkung ist Teil der Abnahme (3.8).

## 4.7 Updates

**System → Updates**: Modus **Automatisch (Stable)** empfohlen, Wartungsfenster festlegen (z. B. Dienstag 22:00–23:00). Details in [Kap. 9.1](09-betrieb-wartung.md#91-updates).
