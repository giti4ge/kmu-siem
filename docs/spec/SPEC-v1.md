# Master-Spezifikation v1 – Open-Source KMU-SIEM & Network-Visibility Appliance

| Dokument-Version | Status |
|---|---|
| **1.0.0** | **Eingefroren / ersetzt** durch [SPEC.md](SPEC.md) (2.x) |

> Dieses Dokument ist die unveränderte Ausgangsspezifikation und wird nur als Referenz aufbewahrt.
> Gültig ist ausschließlich die aktuelle [SPEC.md](SPEC.md). Die Unterschiede zeigt [SPEC-DIFF-v1-v2.md](SPEC-DIFF-v1-v2.md).

---

## 1. Projektziel & Systemkontext

Entwicklung einer schlüsselfertigen, gehärteten, rein auf Open-Source-Komponenten basierenden Virtual Appliance (VMware .ova & Hyper-V .vhdx) auf Basis von Debian 12/13 (Minimal) für KMU-Umgebungen (~50 Endpunkte, 15–40 EPS, ~2–4 GB Logs/Tag).

Kernprinzipien: Stabilität, Reproduzierbarkeit, wartbare Trennung von Code und Kundendaten, 100 % autonomer Betrieb ohne KI-Abhängigkeit, strikte OWASP-Konformität, vollständige Konfiguration über ein eigenes Web-UI.

Ziel-Hardware-Sizing: 4–8 vCPUs, 16 GB RAM, 250–500 GB SSD/NVMe.

## 2. Verzeichnisstruktur & Architektur-Trennung

Der Code-Layer (/opt/siem/app) und der persistente Daten-Layer (/opt/siem/data) müssen strikt getrennt sein, um atomare Funktionsupdates und Rollbacks zu ermöglichen.

```
/opt/siem/
├── install.sh                      # Geführtes Hardening- & Installationsskript (Host-Ebene)
├── updater/                        # Host-seitiger Appliance-Updater-Daemon (Systemd)
│   ├── siem-updater.py             # Ed25519-Signaturprüfung, Pre-Pull, Migration, Rollback
│   └── public_key.ed25519          # Öffentlicher Schlüssel zur Verifikation von Releases
├── app/                            # Versionierter Code-Layer (wird bei Updates ersetzt)
│   ├── docker-compose.yml          # Orchestrierung aller Container
│   ├── .env.template               # Vorlage für Umgebungsvariablen
│   ├── control-plane/              # Eigenes Management-Backend & Web-UI
│   │   ├── backend/                # Python 3.12 + FastAPI + SQLAlchemy + Alembic
│   │   └── frontend/               # React / TypeScript / Tailwind CSS (Single Page App)
│   ├── collectors/                 # Spezialisierte Worker-Container
│   │   ├── arp-guard/              # Python/Scapy Layer-2 Monitor & Nmap Asset Discovery
│   │   ├── snmp-poller/            # Telegraf / Python SNMPv3 Poller (Aruba & FS Switches)
│   │   └── endpoint-integrations/  # Sophos Central API Poller & Ikarus Log-Parser
│   ├── vector/                     # Log-Ingestion, Normalisierung (ECS/OCSF) & Disk-Buffering
│   │   ├── vector.toml             # Basis-Pipeline
│   │   └── parsers/                # VRL-Parser (FortiGate, Aruba, FS, Windows WEF, Ikarus)
│   ├── rules/                      # Sigma-Regelwerk + ElastAlert2 / OpenSearch Security Analytics
│   └── proxy/                      # Caddy / Nginx + ModSecurity (OWASP Core Rule Set)
├── data/                           # Persistenter Daten-Layer (bleibt bei Updates unberührt)
│   ├── config-db/                  # SQLite (WAL-Mode) oder PostgreSQL für Control-Plane-Config
│   ├── opensearch/                 # OpenSearch Daten-Volumes (180 Tage Retention)
│   ├── vector-buffer/              # Disk-Buffer für unterbrechungsfreie Updates
│   └── certs/                      # Generierte Kunden-Root-CA, Server-Zertifikate & Secrets
└── backups/                        # Automatische Pre-Update-Snapshots (tar.gz)
```

## 3. Technische Spezifikation der Komponenten

### 3.1 Host-Setup & Hardening (install.sh)

OS: Debian 12/13 Minimal.

Hardening (CIS-orientiert):
- Kernel-Parameter (/etc/sysctl.d/99-siem-hardening.conf): SYN-Cookies aktiv, IP-Forwarding aus, ICMP-Redirects aus, ASLR aktiv (kernel.randomize_va_space=2).
- Deaktivierung ungenutzter Module (usb-storage, bluetooth, firewire-core).
- SSH-Hardening (/etc/ssh/sshd_config.d/99-siem.conf): PermitRootLogin no, moderne Ciphers/KEX, MaxAuthTries 3.
- Einrichtung von unattended-upgrades für tägliche OS-Sicherheitspatches (konfigurierbares Reboot-Fenster).

Firewall (nftables):
- Policy: input drop, forward drop, output accept.
- Explizit geöffnete Ports: 22/tcp (SSH), 443/tcp (Web-UI), 514/udp+tcp (Syslog Plain), 6514/tcp (Syslog TLS), 5985-5986/tcp (Windows Event Forwarding / WinRM), 162/udp (SNMP Traps).
- Muss über ein validiertes Privileged-Helper-Skript vom Web-UI aus auf definierte Management-IPs/Subnetze einschränkbar sein (inkl. 60-Sekunden-Dead-Man's-Switch-Rollback).

### 3.2 Log-Ingestion, Normalisierung & Datenbank

Ingestion (Vector):
- Nimmt Syslog (RFC 3164/5424, TLS), CEF und JSON entgegen.
- Normalisiert alle Logs über Vector Remap Language (VRL) auf ein einheitliches Schema (ECS – Elastic Common Schema).
- Nutzt Disk-Buffering, damit während Container-Neustarts/Updates keine Logs verloren gehen.

Agentless Windows-Anbindung (OpenWEC + Vector):
- Keine Third-Party-Agents auf Windows-Clients/Servern.
- Empfang nativer Windows Event Forwarding (WEF) Subscriptions via WinRM/HTTPS (Port 5985/5986) über OpenWEC (Rust-basierter Collector), Weiterleitung als strukturiertes JSON an Vector.

Datenbank (OpenSearch):
- Single-Node-Konfiguration mit optimiertem JVM-Heap (50 % des System-RAMs, max. 8 GB).
- Index State Management (ISM) – Standard 180 Tage:
  - Tägliche Index-Rotation: siem-logs-YYYY.MM.DD.
  - Hot (Tag 1–30): Volle Schreib-/Leseleistung.
  - Warm (Tag 31–180): Automatisches force_merge, best_compression (ZSTD), read_only.
  - Delete (ab Tag 181): Automatische Löschung alter Indizes (Retention im Web-UI konfigurierbar zwischen 30 und 730 Tagen).
- Disk-Watermark-Watchdog: Warn-Mail bei 80 % Festplattenbelegung; automatische Notbereinigung ältester Warm-Indizes bei 90 %.

### 3.3 Netzwerk- & Security-Integrationen

Switches (Aruba & FS.com):
- Kombination aus Syslog (Echtzeit-Events wie Link Up/Down, Auth-Failures) und SNMPv3-Polling (alle 60 Sek.).
- Abgefragte MIBs: IF-MIB (ifOperStatus, ifHighSpeed, ifAlias), Q-BRIDGE-MIB (VLAN-Zuordnung per Port), BRIDGE-MIB (MAC-Address-Table).
- Mapping der MAC-Adressen auf Hersteller via lokaler, regelmäßig aktualisierter IEEE-OUI-Datenbank.

Firewalls (Fortinet FortiGate):
- Syslog-TLS (Port 6514) im Key-Value- oder CEF-Format. Parsing von Traffic-Logs (Inter-VLAN-Visibility), IPS/AV-Events, Admin-Logins und VPN-Verbindungen.

Virenscanner / EDR:
- Sophos XDR / Central: REST-API-Poller (OAuth2 Client Credentials) gegen die Sophos Central SIEM API (Alerts & XDR-Events).
- Ikarus Security: Syslog-Parser für IKARUS security.manager / mail.security / web.security.

### 3.4 Multi-Segment-Monitoring, Asset Discovery & ARP-Guard

Mehrere Netzwerksegmente (VLANs):
- Unterstützung eines sekundären Trunk-Interfaces (eth1, VMware VLAN 4095 / Hyper-V Trunk) mit passiven 802.1Q-Sub-Interfaces (eth1.<vlan_id>) ohne eigene IP-Adresse (Stealth-Mode für Layer-2-Sichtbarkeit ohne Angriffsfläche).
- Alternativ für L3-getrennte Netze: Kombination aus Switch-SNMPv3-Tabellen und DHCP-Logs.

Active Asset Discovery (nmap):
- Zeitgesteuerter oder manueller Scan definierter Kunden-Subnetze. Unbekannte Hosts landen im Web-UI in einer Discovery-Inbox zur 1-Klick-Klassifizierung (Firewall, Switch, Windows-Host, Ignorieren).

ARP-Guard (Scapy / libpcap Daemon):
- Passives Mithören auf allen konfigurierten Interfaces/VLANs. Pflege einer Asset-Tabelle (MAC, IP, VLAN, OUI-Hersteller, first_seen, last_seen).
- Alarmierung bei: New Station (unbekannte MAC), MAC-Flip-Flop / ARP-Spoofing (bekannte IP wechselt MAC), Re-Appearance (Gerät nach > X Tagen wieder online).

### 3.5 Detection Engine, Granulares Alerting & Optionale KI-Bridge

Deterministischer Kern (100 % ohne KI):
- Sigma-Regeln (automatisch in OpenSearch-Queries konvertiert) + interne Korrelationsregeln (z. B. Heartbeat-Watchdog, der alarmiert, wenn eine Firewall/DC > 15 Min. keine Logs sendet).

Granulare Benachrichtigungs-Matrix (SMTP), konfigurierbar pro Regel-Kategorie und Severity (Info, Low, Medium, High, Critical):
- Sofort-E-Mail (inkl. Deduplizierung / Throttling, um Mail-Stürme zu verhindern).
- Sammel-Digest (täglicher/wöchentlicher Morgen-Report für Low/Medium-Events).
- Silent Log (nur Dashboard).
- Unterstützung von Wartungsfenstern (Unterdrückung von Verfügbarkeits-Alarmen während Patch-Days).

Optionale KI-Bedrohungsanalyse (Zuschaltbar im Web-UI):
- Anbindung an lokales LLM (Ollama / OpenAI-kompatibler Endpoint) oder externe API (mit vorgeschaltetem PII-Anonymizer für IPs/Hostnamen/Usernamen).
- Funktion: Zeitgesteuerter Anomalie-Digest über ungewöhnliche Log-Muster sowie automatische Klartext-Erklärung und Handlungsempfehlung bei kritischen Alerts.

### 3.6 Update-Architektur (Content & Feature-Releases)

- Kanal 1 – Content & Security (Täglich automatisch): Debian unattended-upgrades, Sigma-Rules, Threat-Intel-Feeds (IOCs) und IEEE-OUI-Listen. Hot-Reload ohne Service-Unterbrechung.
- Kanal 2 – Funktions- & Softwareupdates (Release-basiert):
  - Gesteuert durch den Host-Daemon siem-updater.py.
  - Ablauf: Download release.json → Ed25519-Signaturprüfung → Backup von /opt/siem/data/config-db & /opt/siem/app → docker compose pull → Alembic DB-Migration → Container-Neustart → 60s Healthcheck → Automatischer Rollback bei Fehler.
  - Im Web-UI umschaltbar zwischen Auto-Update (Stable), Manuell per Klick und Release-Channel (Stable / Beta).

## 4. Control-Plane & Web-UI Anforderungen (OWASP-konform)

Security (OWASP Top 10):
- Reverse Proxy mit TLS 1.3 (eigene Root-CA + Upload eigener Zertifikate), OWASP ModSecurity CRS, HSTS, CSP, CSRF-Schutz.
- Strikte Input-Validierung aller Formulare via Pydantic (verhindert Command-Injection bei SNMP/Nmap/Firewall-Konfigurationen).
- RBAC (Rollenmodell): System-Admin (Vollzugriff + System/Firewall/Updates), Security-Analyst (Regeln, Alerts, Forensik), Auditor / Read-Only (nur Dashboards). Optionale TOTP-MFA.
- Unveränderliches Audit-Log für alle Konfigurationsänderungen.

Erforderliche Web-UI-Module:
- Executive & Network Status Dashboard: Ampelstatus aller Systeme, Top-Alerts, Firewall-Blocks, EPS-Metriken.
- Switch-Port-Matrix: Visuelle Darstellung pro Aruba/FS-Switch (Port-Nummer, Link-Status, Speed 10M/100M/1G/10G, Untagged/Tagged VLANs, verbundene MACs + Hersteller).
- Asset & ARP-Guard Center: Live-Geräteliste, Discovery-Inbox für neue nmap-Funde, ARP-Spoofing-Historie, MAC-Whitelisting.
- Log-Explorer & KI-Insights: Schnelle Suche über OpenSearch-Logs + KI-Anomalie-Berichte.
- Konfiguration & Alert-Matrix: Geräte-Onboarding (Fortinet, Switches, Sophos, Ikarus, VLAN-Trunks), granulares E-Mail-Routing, Retention-Slider.
- System, Firewall & Updates: nftables-IP-Whitelisting, SMTP-Setup, KI-API-Konfiguration, Update-Manager & 1-Klick-Rollback.

## 5. Empfohlene Entwicklungsreihenfolge für den KI-Agenten

- Phase 1 (Grundgerüst & Infrastruktur): Repository-Struktur anlegen, install.sh (Debian Hardening + nftables + Docker), docker-compose.yml (OpenSearch + ISM-Policy, Vector, Reverse Proxy).
- Phase 2 (Control Plane & Auth): FastAPI-Backend mit SQLite/Alembic-Schema, RBAC + TOTP-MFA, Audit-Logging und React-Grundgerüst mit Login & Dashboard-Layout.
- Phase 3 (Ingest & Parser): Vector-Pipelines für FortiGate, Windows WEF (OpenWEC), Sophos API und Ikarus sowie Config-Generator aus der Control-Plane-DB.
- Phase 4 (Netzwerk-Sensoren): SNMPv3-Poller (Aruba/FS MIB-Parser + Switch-Port-Matrix UI), nmap-Discovery-Worker und Scapy ARP-Guard-Daemon inkl. VLAN-Trunk-Support.
- Phase 5 (Alerting, KI-Bridge & Updater): Granulare Alert-Engine (SMTP + Digest + Throttling), optionale KI-Schnittstelle (Ollama/OpenAI + Anonymizer) und siem-updater.py mit Ed25519-Verifikation und Rollback.
