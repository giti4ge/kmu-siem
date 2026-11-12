# Anhang

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.4.0)

## A. Ports

### Eingehend zur Appliance

| Port | Protokoll | Dienst | Quelle |
|---|---|---|---|
| 22 | TCP | SSH (Wartung) | Admin-Arbeitsplätze, Dienstleister |
| 443 | TCP | Web-UI, API, Health-Check | Admin-Netz, Monitoring |
| 514 | UDP/TCP | Syslog | Switches, Ikarus, sonstige |
| 6514 | TCP | Syslog über TLS | FortiGate, Linux-Server |
| 5985 | TCP | Windows-Ereignisweiterleitung (Kerberos) | Windows-Server/-Clients |
| 5986 | TCP | Windows-Ereignisweiterleitung (HTTPS, optional) | Nicht-Domänen-Server |
| 162 | UDP | SNMP-Traps | Switches |

### Interne Ports (nicht direkt von außen erreichbar)

| Port | Dienst | Hinweis |
|---|---|---|
| 8443/tcp | Proxy (HTTPS) | Ziel der Umleitung von 443 |
| 8080/tcp | Proxy (HTTP, nur 127.0.0.1) | Weiterleitung auf HTTPS, Health-Check |
| 10514/tcp+udp | Vector (Syslog) | Ziel der Umleitung von 514 |
| 10162/udp | SNMP-Traps | Ziel der Umleitung von 162 (ab Phase 4) |
| 9200, 9300/tcp | OpenSearch | nur 127.0.0.1 |
| 8686/tcp | Vector-API | nur 127.0.0.1 |

### Ausgehend von der Appliance

| Ziel | Port | Zweck |
|---|---|---|
| DNS-Server | 53 UDP/TCP | Namensauflösung |
| NTP-Server | 123 UDP | Zeit |
| Switches | 161 UDP | SNMP-Abfrage |
| FortiGate | 443 TCP | REST-API |
| SMTP-Server | 25/465/587 TCP | E-Mail |
| Internet (direkt oder Proxy) | 443 TCP | Debian, Docker, GitHub (Releases, API, `ghcr.io`), Sophos Central, Teams-Webhook, abuse.ch, IEEE, Zeitstempeldienst, KI-Anbieter |
| Langzeitarchiv | 443 / 445 / 2049 / 22 TCP | S3 / SMB / NFS / SFTP |
| Domain Controller | 88 TCP/UDP | Kerberos (Validierung der Keytab) |
| Kundennetze (Discovery) | diverse | Aktive Asset-Discovery |

## B. Windows-Ereignis-IDs

Auswahl der gesammelten und ausgewerteten Ereignisse. Die vollständige Liste je Subscription ist im Web-UI unter **Quellen → Windows → Subscriptions** einsehbar.

| ID | Bedeutung | Rolle |
|---|---|---|
| 1102 / 104 | Sicherheits-/Ereignisprotokoll gelöscht | alle |
| 4624 / 4625 | Anmeldung erfolgreich / fehlgeschlagen | alle |
| 4634 / 4647 | Abmeldung | DC |
| 4648 | Anmeldung mit expliziten Anmeldeinformationen | alle |
| 4662 | Operation an AD-Objekt (selektiv, z. B. DCSync-Erkennung) | DC |
| 4663 / 4660 / 4670 | Dateizugriff / Löschung / Berechtigungsänderung (FIM) | FIM-Server |
| 4672 | Spezielle Rechte bei Anmeldung | alle |
| 4688 | Neuer Prozess (mit Kommandozeile) | Member-Server |
| 4697 / 7045 | Dienst installiert | alle |
| 4698–4702 | Geplanter Task angelegt/gelöscht/aktiviert/deaktiviert/geändert | alle |
| 4719 | Audit-Policy geändert | alle |
| 4720–4767 | Konten- und Gruppenverwaltung | DC |
| 4768 / 4769 / 4771 | Kerberos TGT / Service-Ticket / Pre-Auth fehlgeschlagen | DC |
| 4776 | NTLM-Authentifizierung | DC |
| 4794 | DSRM-Kennwort gesetzt | DC |
| 5136 / 5137 / 5139 / 5141 | AD-Objekt geändert / erstellt / verschoben / gelöscht | DC |
| 5145 | Zugriff auf Netzwerkfreigabe (FIM, selektiv) | FIM-Server |
| 6416 | Neues externes Gerät erkannt | Clients (optional) |
| 4104 | PowerShell-Skriptblock | Member-Server |

## C. Log-Kategorien

Siehe [Kapitel 2.5](02-systemueberblick.md#25-log-kategorien).

## D. Befehle auf der Appliance (SSH)

| Befehl | Zweck |
|---|---|
| `sudo /opt/siem/host/install.sh --preflight` | Voraussetzungen prüfen |
| `sudo /opt/siem/host/install.sh --repair` | Sollzustand wiederherstellen |
| `sudo siem-hostd system status` | Status von Diensten, Speicher, Versionen |
| `sudo siem-hostd system storage-grow` | Daten-Disk nach Vergrößerung erweitern |
| `sudo siem-hostd update check \| list \| apply [--version vX.Y.Z] \| rollback` | Updates von GitHub |
| `sudo siem-hostd update set-token --file <datei>` | GitHub-Zugangstoken setzen/erneuern |
| `sudo siem-hostd backup create` | Backup sofort erstellen |
| `sudo siem-hostd firewall show` | Gespeicherte Freigaben und ggf. unbestätigte Änderung anzeigen |
| `sudo siem-hostd firewall apply --file <json>` | Freigaben ändern (Bestätigung innerhalb von 60 s, sonst automatische Rücknahme) |
| `sudo siem-hostd firewall confirm <token>` / `rollback` | Unbestätigte Änderung bestätigen bzw. sofort zurücknehmen |
| `sudo journalctl -u siem-hostd`, `/var/log/siem-hostd.log` | Protokoll und Audit-Log von siem-hostd |

## E. Dateien und Protokolle

| Pfad | Inhalt |
|---|---|
| `/var/log/siem-install.log` | Installations- und Reparaturprotokoll |
| `/var/lib/siem/install.state` | Fortschritt der Installation (für `--resume`) |
| `/opt/siem/app/current` | Verweis auf die aktive Version |
| `/opt/siem/data/` | Alle Daten (nicht manuell verändern) |
| `/opt/siem/backups/` | Lokale Backups |

## F. Glossar

| Begriff | Erklärung |
|---|---|
| **Active Response** | Automatische oder manuelle Gegenmaßnahme, hier: IP-Sperre auf der FortiGate |
| **ARP-Guard** | Überwachung von IP-/MAC-Zuordnungen zur Erkennung neuer Geräte und von Spoofing |
| **ECS** | Elastic Common Schema – einheitliches Feldschema für alle Ereignisse |
| **EPS** | Events per Second – Ereignisse pro Sekunde |
| **FDB** | Forwarding Database – MAC-Adresstabelle eines Switches |
| **FIM** | File-Integrity-Monitoring – Überwachung von Dateiänderungen |
| **Hash-Kette** | Verkettung von Prüfsummen, sodass jede Veränderung oder Lücke erkennbar ist |
| **Heartbeat** | Überwachung, ob eine Quelle regelmäßig Ereignisse sendet |
| **IOC** | Indicator of Compromise – bekannte schädliche IP, Domain oder Datei |
| **Keytab** | Datei mit dem Kerberos-Schlüssel eines Dienstkontos |
| **Preflight** | Prüfung der Voraussetzungen vor der Installation, ohne Änderungen |
| **Retention** | Aufbewahrungsdauer |
| **SACL** | System Access Control List – Überwachungseinträge für Dateien/Objekte unter Windows |
| **Sigma** | Herstellerunabhängiges Format für Erkennungsregeln |
| **SPN** | Service Principal Name – Kerberos-Dienstname |
| **Unparsed** | Ereignisse, die kein Parser erkannt hat |
| **WEF** | Windows Event Forwarding – in Windows eingebaute Ereignisweiterleitung |
| **WORM** | Write Once Read Many – unveränderbarer Speicher |
