# 2. Systemüberblick

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.3.0)

## 2.1 Architektur

```
                    ┌──────────────────────── Appliance (Debian 13) ────────────────────────┐
FortiGate ─TLS 6514─┤                                                                        │
Switches ──514/162──┤  vector ──► opensearch ◄── worker (Alarme, Reports, Archiv, KI)        │──► E-Mail / Teams
Linux ────TLS 6514──┤    ▲  │                        ▲                                        │──► FortiGate (Sperre)
Windows ──WEF 5985──┤ openwec│ archive               api ◄── proxy (443) ◄── Browser          │──► Langzeitarchiv
                    │    ▲  ▼                        ▲                                        │
                    │ snmp, net-sensor, integrations │ siem-hostd (Host: Firewall, Updates)   │
                    └────────────────────────────────────────────────────────────────────────┘
Sophos Central ◄── HTTPS (Abfrage) ── integrations
```

## 2.2 Komponenten

| Dienst | Aufgabe | Technik |
|---|---|---|
| `proxy` | Einziger Zugang zum Web-UI, TLS 1.3, Web Application Firewall | nginx, ModSecurity, OWASP CRS |
| `api` | Programmierschnittstelle des Web-UI, Anmeldung, Rechteprüfung, Konfiguration | Python, FastAPI |
| `worker` | Alarm-Engine, Benachrichtigungen, Reports, Archiv-Versiegelung, Speicher-Wächter, KI-Anbindung, Content-Updates | Python |
| `frontend` | Web-Oberfläche | React |
| `opensearch` | Speicherung und Suche aller Ereignisse | OpenSearch |
| `dashboards` | Tiefenanalyse für Analysten | OpenSearch Dashboards |
| `vector` | Annahme, Normalisierung, Anreicherung und Zwischenspeicherung aller Logs | Vector |
| `openwec` | Empfang der Windows-Ereignisweiterleitung | OpenWEC |
| `snmp` | Abfrage der Switches, Empfang von SNMP-Traps | Python, pysnmp |
| `net-sensor` | ARP-Guard und Asset-Discovery | Python, Scapy |
| `integrations` | Abfrage von Sophos Central und FortiGate-API | Python |
| `siem-hostd` | Privilegierte Aktionen auf dem Host (Firewall, Netzwerk, Updates, Backup, Neustart) | Python, systemd |

## 2.3 Verzeichnisse auf der Appliance

| Pfad | Inhalt | Bei Update |
|---|---|---|
| `/opt/siem/host/` | Installations- und Host-Komponenten | ersetzt |
| `/opt/siem/app/` | Anwendung (Container-Definitionen, Parser, Regeln) | ersetzt (versioniert, mit Rollback) |
| `/opt/siem/data/` | Konfiguration, Ereignisse, Archiv, Zertifikate, Schlüssel | **bleibt erhalten** |
| `/opt/siem/backups/` | Sicherungen vor Updates und geplante Backups | bleibt erhalten |

## 2.4 Weg eines Ereignisses

1. **Annahme:** Ein Gerät sendet ein Ereignis (Syslog, WEF) oder es wird abgeholt (Sophos, SNMP).
2. **Zwischenspeicher:** Vector schreibt es zuerst in einen Disk-Puffer. Bei Neustarts oder Updates gehen über TCP/TLS gesendete Ereignisse daher nicht verloren.
3. **Normalisierung:** Ein gerätespezifischer Parser übersetzt das Ereignis in das einheitliche Schema ECS. Erkennt ihn kein Parser, landet das Ereignis in der Kategorie `unparsed`.
4. **Anreicherung:** Hersteller der MAC-Adresse, Asset-Informationen, Treffer in Threat-Intel-Listen, bei Bedarf Pseudonymisierung.
5. **Speicherung:** Ablage in OpenSearch (durchsuchbar) **und** im Archiv (versiegelt, unveränderlich).
6. **Auswertung:** Die Alarm-Engine prüft regelmäßig alle aktiven Regeln. Treffer erzeugen Alarme.
7. **Benachrichtigung:** Gemäß Alarm-Matrix per E-Mail/Teams, sofort oder als Digest.

## 2.5 Log-Kategorien

Alle Einstellungen zu Aufbewahrung, Rechten und Vier-Augen-Prinzip erfolgen je Kategorie.

| Kategorie | Inhalt | Standard-Aufbewahrung (Index) |
|---|---|---|
| `firewall` | FortiGate Traffic, UTM, VPN, Admin | 180 Tage |
| `windows` | Windows-Ereignisse aller Server/Clients | 180 Tage |
| `linux` | Linux-Server | 180 Tage |
| `network` | Switches, SNMP-Traps | 180 Tage |
| `edr` | Sophos | 180 Tage |
| `av` | Ikarus | 180 Tage |
| `asset` | ARP-Guard, Discovery, Asset-Änderungen | 180 Tage |
| `alerts` | Erzeugte Alarme | 365 Tage |
| `audit` | Audit-Log der Appliance | 365 Tage |
| `system` | Selbstüberwachung | 90 Tage |
| `unparsed` | Nicht erkannte Ereignisse | 14 Tage |

> **Hinweis:** Die Kategorie `ot` ist für eine spätere Version reserviert.

## 2.6 Mengengerüst und Grenzen

| Parameter | Ausgelegt für |
|---|---|
| Endpunkte | ca. 50 |
| Ereignisse/Sekunde | Ø 15–40, Spitzen bis 300 |
| Datenmenge | 2–4 GB Rohdaten pro Tag |
| Aufbewahrung | abhängig von Disk-Größe; das Web-UI zeigt die Prognose |

Deutlich höhere Mengen (z. B. vollständiges Traffic-Logging großer Firewalls) erfordern mehr Speicher und RAM, siehe [Kap. 3.2](03-installation.md#32-systemanforderungen).
