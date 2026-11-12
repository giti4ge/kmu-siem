# Master-Spezifikation – KMU-SIEM & Network-Visibility Appliance

| Dokument-Version | Stand | Status | Ersetzt |
|---|---|---|---|
| **2.3.0** | 2026-11-13 | Freigabe ausstehend | [SPEC-v1.md](SPEC-v1.md) (1.0.0) |

**Änderungshistorie:** siehe [SPEC-HISTORY.md](SPEC-HISTORY.md). Den detaillierten Vergleich v1 ↔ v2 enthält [SPEC-DIFF-v1-v2.md](SPEC-DIFF-v1-v2.md).

---

## 0. Änderungen gegenüber v1 (Kurzfassung)

| Bereich | v1 | v2 |
|---|---|---|
| **Auslieferung** | Fertige Vorlage `.ova` / `.vhdx` | **Ausschließlich `install.sh`** auf einer frischen, schlanken Debian-13-VM mit SSH; keine VM-Vorlagen mehr (ab 2.3.0) |
| Betriebssystem | Debian 12/13 | **Debian 13 (trixie)** fix |
| Log-Schema | ECS/OCSF | **ECS** ausschließlich |
| Detection | Sigma + ElastAlert2 / OS Security Analytics | **Eine eigene Alert-Engine** (pySigma → OpenSearch-Queries) |
| Log-Explorer | eigenes UI | **Hybrid**: eigenes UI (Schnellsuche) + OpenSearch Dashboards (SSO, Tiefenanalyse) |
| Asset Discovery | nmap | **Eigener Python-Scanner** (Lizenz: NPSL ungeeignet für Mitlieferung) |
| ARP-Guard | rein passiv am Trunk | Passiv (Broadcasts) **+ Korrelation Switch-FDB & FortiGate-ARP-Tabelle** (kein Port-Mirror verfügbar) |
| Docker-Netzwerk | nicht spezifiziert | Ingest/Sensoren `network_mode: host`, nftables ohne Docker-iptables-Bypass |
| Retention | global 180 Tage | **Je Log-Kategorie** einstellbar |
| Datenschutz | – | **Optionaler Datenschutzmodus** (Pseudonymisierung, Vier-Augen-Aufdeckung) |
| Alarmierung | SMTP | **E-Mail + MS Teams** (Workflows-Webhook) |
| KI | lokal (Ollama) oder extern | **Nur externe APIs**, Anonymizer verpflichtend |
| Active Response | – | **FortiGate-IP-Sperre**: manuell und optional regelbasiert automatisch |
| Sophos | SIEM-API | **XDR Data Lake Queries primär**, Fallback SIEM Events/Alerts API |
| Windows | WEF 5985/5986 | WEF über **Kerberos/5985** (Standard), Onboarding-Assistent mit PowerShell-Skript |
| Config-DB | SQLite oder PostgreSQL | **SQLite (WAL)** |
| Updates | Signatur auf release.json | + **Image-Digest-Pinning**, Downgrade-Schutz, OpenSearch-Snapshot vor Update |
| Sizing | 250–500 GB | **min. 500 GB**, Heap 4–6 GB |
| Archivierung | – | **Revisionssicheres Archiv** (Hash-Kette, Signatur, optional RFC-3161-Zeitstempel) + externes Langzeitarchiv |
| Reporting | Digest | **Report-Engine** (PDF/HTML/CSV, geplant per Mail, Compliance-Vorlagen NIS2/ISO 27001/DSGVO) |
| Windows | – | **Change-Auditing** (AD, GPO, Gruppen, Server) + **agentloses File-Integrity-Monitoring** (SACL) + Audit-Policy-Check |
| Quellen | – | **Linux-Server agentlos** (rsyslog/journald TLS), optional Windows-Clients per WEF |
| Rollen | 3 feste Rollen | **Granulares Rollenkonzept** mit Datenbereichen + Vier-Augen-Prinzip für Events, Alarme und Archiv |
| UI | – | **Mehrsprachig** (DE/EN), Regel-Import/-Export, System-Protokoll |

---

## 1. Projektziel & Rahmenbedingungen

Gehärtete SIEM-Appliance für KMU-Umgebungen, ausschließlich aus Open-Source-Komponenten. Sie entsteht durch **ein einziges Installationsskript (`install.sh`) auf einer frischen, schlanken Debian-13-VM**. Das Skript installiert alle Abhängigkeiten, härtet das System und richtet die Anwendung ein. Fertige VM-Vorlagen (`.ova`, `.vhdx`) werden **nicht** ausgeliefert.

| Parameter | Wert |
|---|---|
| Ausgangssituation | Neue Debian-13-VM (amd64), Minimalinstallation mit SSH-Server und Standard-Systemwerkzeugen, ohne Desktop; feste IP-Adresse; Hypervisor beliebig (VMware, Hyper-V, Proxmox u. a.) |
| Umgebung | ~50 Endpunkte, angebundene Server: DCs, Exchange, Member-Server |
| Last (Planwert) | 15–40 EPS Ø, Peaks bis 300 EPS; 2–4 GB Rohlogs/Tag |
| Betrieb | Beim Kunden, Bestandteil der Dienstleistung (kein Verkauf, kein Air-Gap) |
| Zugriff Dienstleister | SSH und Web-UI über das Kundennetz; kein Fernzugriffs-Tunnel |
| Alarmierung | ausschließlich E-Mail und MS Teams |
| Internet | Im Regelfall vorhanden, HTTP(S)-Proxy mit optionaler Authentifizierung unterstützt |
| Hochverfügbarkeit | Nicht vorgesehen (Single Node) |

**Kernprinzipien:** Stabilität, Reproduzierbarkeit, strikte Trennung Code/Daten, autonomer Betrieb ohne KI, OWASP ASVS 4.0 Level 2 als Prüfmaßstab, vollständige Konfiguration über das Web-UI.

### 1.1 Sizing

| Ressource | Minimum | Empfohlen |
|---|---|---|
| vCPU | 4 | 6–8 |
| RAM | 16 GB | 24 GB |
| Disk (Daten) | 500 GB SSD | 750 GB–1 TB SSD/NVMe |
| OpenSearch-Heap | 4 GB | 6 GB (nie > 50 % RAM, nie > 8 GB) |

Das lokale Archiv belegt zusätzlich ca. 15–25 % der Rohdatenmenge (zstd). Bei Langzeitaufbewahrung liegt es deshalb auf dem externen Langzeitarchiv, lokal nur so lange wie nötig (Standard 30 Tage).

**Disk-Layout (empfohlen):** **Disk 1** (≥ 40 GB) mit dem Debian-System, **Disk 2** (leer, ohne Partition) für Daten. `install.sh` erkennt Disk 2, richtet LVM ein (VG `siem`, LV `data`, ext4/XFS, online erweiterbar) und hängt sie unter `/opt/siem/data` ein, `/opt/siem/backups` liegt ebenfalls dort. Ohne zweite Disk installiert das Skript nach Warnung auf Disk 1, sofern dort genug Platz frei ist.

---

## 2. Verzeichnisstruktur

```
/opt/siem/
├── host/                            # Host-Komponenten (root, systemd)
│   ├── install.sh                   # Erstinstallation & Hardening (idempotent)
│   ├── siem-hostd/                  # Privilegierter Host-Daemon (Allowlist-API, Unix-Socket)
│   │   ├── hostd.py
│   │   ├── actions/                 # firewall.py, network.py, update.py, system.py, backup.py
│   │   └── public_keys/             # Ed25519 Release-Keys (Rotation: mehrere Keys zulässig)
│   └── systemd/                     # siem-hostd.service, siem-stack.service, Timer
├── app/                             # Versionierter Code-Layer (wird bei Updates ersetzt)
│   ├── VERSION
│   ├── docker-compose.yml
│   ├── control-plane/
│   │   ├── backend/                 # Python 3.12, FastAPI, SQLAlchemy 2, Alembic, Pydantic v2
│   │   ├── worker/                  # Scheduler, Alert-Engine, Notifier, Digest, KI-Bridge
│   │   └── frontend/                # React, TypeScript, Tailwind, TanStack Query
│   ├── sensors/
│   │   ├── net-sensor/              # ARP-Guard + Discovery-Scanner (Scapy, host network)
│   │   └── snmp/                    # SNMPv3-Poller + Trap-Receiver (pysnmp)
│   ├── integrations/                # Sophos Central (XDR Data Lake / SIEM API), FortiGate REST API
│   ├── vector/
│   │   ├── vector.yaml.j2           # Template, gerendert aus der Config-DB
│   │   └── vrl/                     # fortigate, aruba_os, aruba_instant_on, fs_s3900, windows, ikarus, sophos, generic
│   ├── openwec/                     # OpenWEC-Konfiguration & Subscription-Templates
│   ├── opensearch/                  # Index-Templates, ISM-Policies, Security-Konfiguration
│   ├── dashboards/                  # OpenSearch Dashboards: Saved Objects (Index-Patterns, Visualisierungen)
│   ├── rules/
│   │   ├── sigma/                   # Kuratiertes Sigma-Set (DRL 1.1, Attribution)
│   │   └── internal/                # Korrelations-/Heartbeat-/Asset-Regeln (YAML)
│   └── proxy/                       # nginx + ModSecurity v3 + OWASP CRS 4
├── data/                            # Persistent, von Updates unberührt
│   ├── config-db/                   # siem.db (SQLite WAL)
│   ├── opensearch/
│   ├── opensearch-snapshots/        # Lokales Snapshot-Repository
│   ├── vector-buffer/
│   ├── openwec/                     # OpenWEC-State (Bookmarks/Subscriptions)
│   ├── archive/                     # Versiegeltes Rohdaten-Archiv (Hash-Kette, Signaturen)
│   ├── reports/                     # Erzeugte Reports (Historie)
│   ├── content/                     # Sigma-Updates, IOC-Feeds, OUI-DB (Kanal 1)
│   └── secrets/                     # CA, Zertifikate, Keytab, Master-Key (0700, root)
└── backups/                         # Pre-Update- und geplante Config-Backups
```

---

## 3. Architektur

### 3.1 Container & Dienste

| Dienst | Technik | Netzwerk | Zweck |
|---|---|---|---|
| `proxy` | nginx + ModSecurity v3 + CRS 4 | host (443) | TLS 1.3, WAF, Security-Header, Routing UI/API/Dashboards |
| `api` | FastAPI | bridge `siem-internal` | REST-API, AuthN/AuthZ, Konfiguration |
| `worker` | Python (APScheduler) | bridge | Alert-Engine, Notifier, Digests, Heartbeat, KI-Bridge, Content-Updates |
| `frontend` | statisch via proxy | – | SPA |
| `opensearch` | OpenSearch (Version im Manifest gepinnt) | bridge | Speicher & Suche, Security-Plugin aktiv, internes TLS |
| `dashboards` | OpenSearch Dashboards | bridge | Tiefenanalyse, SSO per Proxy-Auth |
| `vector` | Vector | **host** (514, 6514) | Ingest, Normalisierung, Disk-Buffer |
| `openwec` | OpenWEC | **host** (5985, opt. 5986) | Windows Event Forwarding |
| `snmp` | Python/pysnmp | **host** (162/udp) | SNMPv3-Polling, Trap-Empfang |
| `net-sensor` | Python/Scapy | **host**, `NET_RAW`/`NET_ADMIN` | ARP-Guard, Discovery |
| `integrations` | Python | bridge | Sophos-, FortiGate-API |

Alle Container: Non-root (Ausnahme `net-sensor` mit minimalen Capabilities), read-only Root-FS, `no-new-privileges`, Ressourcen-Limits, Healthchecks, Images per Digest gepinnt.

### 3.2 Datenfluss

```
Syslog/TLS ─┐
WEF ─► OpenWEC ─┤
SNMP-Traps ─► snmp ─┤
Sophos/FortiGate API ─► integrations ─┼─► Vector (VRL → ECS, IOC-Anreicherung, Pseudonymisierung)
net-sensor Events ─┘                         │ Disk-Buffer
                                             ▼
                                        OpenSearch ◄── worker (Alert-Engine: Sigma + intern)
                                             ▲                   │
                                     api / dashboards            ├─► E-Mail / MS Teams
                                                                 └─► FortiGate (Active Response)
```

Nicht zuordenbare Logs landen **nicht im Nirwana**, sondern im Index `siem-unparsed-*` und im UI-Bereich „Unparsed“ (Parser-Entwicklung ohne vorhandene Beispiel-Logs).

### 3.3 Host-Daemon `siem-hostd`

Einzige Brücke zwischen Web-UI und Host. Kein Docker-Socket in Containern.

- Unix-Socket `/run/siem/hostd.sock`, nur in `api` gemountet.
- **Feste Aktions-Allowlist** mit Pydantic-validierten Parametern: `firewall.apply`, `firewall.confirm`, `network.vlan.apply`, `update.check|apply|rollback`, `backup.create|restore`, `system.reboot`, `system.ntp.set`, `system.proxy.set`, `system.status`.
- Keine Shell-Interpolation (`subprocess` mit Argumentlisten), jede Aktion im Audit-Log.
- Kritische Aktionen nur für System-Admin mit frischer MFA-Bestätigung (Re-Auth ≤ 5 min).

---

## 4. Komponentenspezifikation

### 4.1 Host-Setup & Hardening (`install.sh`)

`install.sh` ist der **einzige Installationsweg**. Er erledigt Abhängigkeiten, Härtung und Anwendung in einem Durchlauf.

**Bereitstellung:**
- Installationspaket `siem-installer-<version>.tar.gz` mit `SHA256SUMS` und Ed25519-Signatur (später GitHub Releases).
- Das Skript prüft die Integrität seiner Bestandteile gegen das signierte Manifest, bevor es Änderungen vornimmt.

**Betriebsarten:**

| Aufruf | Zweck |
|---|---|
| `sudo ./install.sh` | Interaktive Installation (Dialoge in der SSH-Sitzung, DE/EN) |
| `sudo ./install.sh --preflight` | Nur Voraussetzungen prüfen, nichts ändern |
| `sudo ./install.sh --unattended antworten.env` | Unbeaufsichtigte Installation mit Antwortdatei |
| `sudo ./install.sh --resume` | Abgebrochene Installation am letzten erfolgreichen Schritt fortsetzen |
| `sudo ./install.sh --repair` | Idempotenter Neu-Durchlauf: stellt Härtung, Pakete und Dienste auf Sollzustand zurück, ohne Daten zu verändern |

**Ablauf (jeder Schritt idempotent, Zustand in `/var/lib/siem/install.state`, Log in `/var/log/siem-install.log`):**
1. **Preflight**: Debian 13 amd64, root/sudo, CPU/RAM/Disk gemäß Sizing, Internet bzw. Proxy erreichbar (Debian-Spiegel, Docker-Repository, Container-Registry, Update-Server), Zeit synchron, DNS, feste IP (Warnung bei DHCP), keine Konflikte mit belegten Ports oder vorhandenem Docker. Bei hartem Fehler wird abgebrochen, ohne etwas zu ändern.
2. **Abfragen** (interaktiv oder aus Antwortdatei): FQDN, NTP-Server, Proxy, Daten-Disk, SSH-Public-Key des Admin-Benutzers, erstes Web-UI-Konto, Sprache, optional VLAN-Trunk-Interface.
3. **Basis**: APT-Quellen (Debian 13 + Sicherheitsupdates), Pakete auf aktuellen Stand, Installation aller Abhängigkeiten (u. a. nftables, chrony, auditd, aide, apparmor, lvm2, unattended-upgrades, python3, jq, curl, ca-certificates).
4. **Daten-Disk** einrichten (LVM, Mount, `fstab` mit UUID).
5. **Härtung** (siehe unten).
6. **Docker Engine** aus dem offiziellen Docker-Repository für Debian, Version im Manifest festgelegt, Daemon-Konfiguration gehärtet.
7. **Firewall** (nftables) mit Standardregeln.
8. **Host-Komponenten**: `siem-hostd`, systemd-Units und Timer.
9. **Anwendung**: `/opt/siem/app/<version>` entpacken, Container-Images **per Digest** laden, Root-CA, Zertifikate, Secrets und Master-Key erzeugen, Stack starten, OpenSearch-Templates/ISM/Security initialisieren, Web-UI-Admin anlegen.
10. **Abschluss-Selbsttest**: alle Dienste healthy, Ende-zu-Ende-Testevent, Firewall aktiv, Härtungsprüfung (Lynis-Kurzlauf). Ausgabe: Web-UI-Adresse, Zertifikats-Fingerabdruck, Zusammenfassung, nächste Schritte.

**Schutz vor Aussperren (SSH):**
- Die Passwort-Anmeldung per SSH wird nur deaktiviert, wenn für den Admin-Benutzer ein gültiger Public Key hinterlegt ist **und** eine Testanmeldung mit diesem Key bestätigt wurde. Sonst bleibt sie aktiv und es gibt eine Warnung.
- Die SSH-Konfiguration wird vor dem Neuladen mit `sshd -t` geprüft. Die laufende Sitzung bleibt erhalten.
- nftables-Regeln lassen die Quell-IP der laufenden SSH-Sitzung immer zu.

**Antwortdatei:** Vorlage `antworten.env.example` im Paket. Secrets können per Datei-Referenz statt im Klartext übergeben werden. Nach erfolgreicher Installation werden Klartext-Secrets aus der Datei entfernt bzw. es wird dazu aufgefordert.

**Härtung:**
- **Debian 13 minimal** als Basis, Logging nach `/var/log/siem-install.log`.
- Es wird ein eigener Admin-Benutzer `siemadmin` angelegt (Gruppe `siem-ssh`, sudo). Ein vom Debian-Installer angelegter Benutzer bleibt erhalten, verliert aber den SSH-Zugang (abschaltbar per Option `--keep-installer-user-ssh`).
- **Kernel/sysctl** (`/etc/sysctl.d/99-siem-hardening.conf`): SYN-Cookies, ICMP-Redirects aus, Source-Route aus, `rp_filter=1`, `randomize_va_space=2`, `kptr_restrict=2`, `dmesg_restrict=1`, `vm.max_map_count=262144` (OpenSearch), `ip_forward=0` (möglich, da keine Docker-Port-Publishings – interne Container-Kommunikation via Bridge benötigt kein Forwarding nach außen; Verifikation in Phase 1).
- **Module** deaktiviert: usb-storage, bluetooth, firewire-core, cramfs, freevxfs, udf.
- **SSH**: `PermitRootLogin no`, nur Key-Auth (Passwort optional während Erstinbetriebnahme), moderne KEX/Ciphers/MACs, `MaxAuthTries 3`, `AllowGroups siem-ssh`.
- **unattended-upgrades** mit konfigurierbarem Reboot-Fenster.
- **chrony** (NTP), Zeitquelle im UI konfigurierbar (Standard: DCs der Domäne). Speicherung UTC, Anzeige Europe/Berlin.
- **auditd** + **AIDE** (Integritätsprüfung, täglich, Abweichung → Alert).
- **AppArmor** aktiv; Docker-Daemon: `userland-proxy: false`, `live-restore: true`, `icc: false`, Log-Rotation.
- Docker: `iptables`-Integration für Bridge-Netz aktiv, aber **keine veröffentlichten Ports**; alle externen Ports über Host-Netzwerk-Container → nftables-INPUT-Regeln greifen vollständig.

### 4.2 Firewall (nftables)

- Policy: input drop, forward drop (Ausnahme Docker-intern), output accept.
- Ports: 22/tcp, 443/tcp, 514/udp+tcp, 6514/tcp, 5985/tcp, 5986/tcp (nur wenn HTTPS-WEF aktiviert), 162/udp.
- **Pro Dienst eigene Quell-Allowlist** im UI (z. B. 514 nur von Switches/FortiGate, 5985 nur von Windows-Servern, 22/443 nur Management-Netze). Standard nach Installation: alle RFC1918-Netze.
- Rate-Limit für neue Verbindungen auf 22/443.
- **Dead-Man's-Switch**: `firewall.apply` aktiviert neue Regeln, startet 60-s-Timer; ohne `firewall.confirm` aus derselben UI-Session automatisches Zurücksetzen.

### 4.3 Ingest & Normalisierung (Vector)

- Quellen: Syslog RFC 3164/5424 (UDP/TCP/TLS), CEF, JSON (HTTP intern von OpenWEC/Sensoren/Integrationen).
- Routing nach Quell-IP → Gerätetyp (aus Config-DB) → passender VRL-Parser; Fallback Auto-Detect; sonst `unparsed`.
- **ECS** als einziges Schema, Felder `event.category`, `event.dataset`, `observer.*`, `source/destination.*`, `user.*`, `host.*`.
- **Anreicherung**: IOC-Abgleich (IP/Domain/Hash) über Vector-Enrichment-Tables, Asset-Kontext (Hostname, Kritikalität), OUI.
- **Disk-Buffer** (`when_full: block`, 10 GB), Metriken → Selbstüberwachung.
- Konfiguration wird aus der Config-DB gerendert, per `vector validate` geprüft, dann Hot-Reload; bei Fehler bleibt die alte Konfiguration aktiv.

### 4.4 Windows-Anbindung (OpenWEC)

- **Standard: Kerberos über HTTP/5985** (Nachrichtenverschlüsselung durch Kerberos), keine Zertifikate auf den Servern nötig.
- **Onboarding-Assistent im Web-UI**:
  1. Eingabe Domäne, FQDN der Appliance, OU(s) der Zielserver.
  2. UI erzeugt signiertes PowerShell-Skript (Download), auszuführen durch Domain-Admin:
     - legt Dienstkonto + SPN `HTTP/<appliance-fqdn>` an, exportiert Keytab,
     - legt GPO „SIEM Event Forwarding“ an (WinRM-Dienst, Subscription Manager URL, Event-Log-Leserechte für NETWORK SERVICE, Audit-Policy-Empfehlungen),
     - optional: DNS-A-Record.
  3. Upload der Keytab im UI → Test-Verbindung → Live-Anzeige eingehender Server.
- **Mitgelieferte Subscriptions** (Rollen-basiert, per OU zuweisbar):
  - *Domain Controller*: Security (4624/4625/4634/4648/4672/4720–4767/4768/4769/4771/4776/5136/5137/4794/4662 selektiv), Directory Service, DNS Server, System.
  - *Exchange*: MSExchange Management (Admin-Audit), Application (MSExchange*), Security, System.
  - *Member-Server*: Security (Logon, Prozess 4688 inkl. Kommandozeile, Dienste 7045, Tasks 4698), System, PowerShell 4104, Defender.
- *Windows-Clients* (optional, per OU): schlanke Subscription (Logon-Fehler, lokale Admin-Änderungen, Defender, Dienstinstallation, USB-Geräte 6416), mit Volumenprognose im UI.
- Optional HTTPS/5986 mit Client-Zertifikaten (für Nicht-Domänen-Server).
- **Audit-Policy-Check**: Das Onboarding-Skript prüft die Advanced Audit Policy und SACL-Voraussetzungen jedes Servers. Abweichungen von der Empfehlung erscheinen im UI als Hardening-Report. Die GPO setzt die empfohlenen Einstellungen. Das entspricht dem „Windows-Hardening mit Bordmitteln“ als ersten Projektschritt.
- Exchange Message Tracking und beliebige Flatfile-Logs: **nicht im Scope** (agentlos nicht abbildbar).

### 4.4a Linux-Server (agentlos)

- Anbindung über die Bordmittel **rsyslog** bzw. **systemd-journald** (journal-upload oder rsyslog-imjournal) per Syslog-TLS 6514.
- Onboarding-Assistent erzeugt ein Konfigurations-Snippet + CA-Zertifikat (Debian/Ubuntu, RHEL-Familie, SUSE).
- Optionale **auditd**-Regeln (Vorlage) für Benutzer-/Sudo-/Dateiänderungen; Weiterleitung über `audisp-syslog`.
- Parser: sshd, sudo, PAM, auditd, systemd, Paketmanager.

### 4.4b Change-Auditing & File-Integrity-Monitoring (agentlos)

**Change-Auditing** – lesbare „Wer hat wann was geändert“-Darstellung aus Windows-Events:
- Active Directory: Objekte erstellt/geändert/gelöscht/verschoben (5136/5137/5139/5141), Attribut alt → neu.
- Benutzer & Gruppen: Anlage, Löschung, Passwort-Reset, Aktivierung/Sperre, Mitgliedschaften (4720–4767), besonders privilegierte Gruppen (Domain/Enterprise/Schema Admins, Backup Operators, …).
- GPO-Änderungen (5136 auf groupPolicyContainer) inklusive Versionszähler.
- Server: Dienstinstallation (7045/4697), geplante Tasks (4698–4702), Audit-Policy-Änderung (4719), Log gelöscht (1102/104), lokale Gruppen.
- Exchange: Admin-Audit-Log (Cmdlet, Ausführender, Parameter).
- Darstellung als Change-Timeline je Objekt/Benutzer, filterbar, als Report exportierbar.

**File-Integrity-Monitoring** – agentlos über Windows-Objektzugriffs-Auditing:
- Im UI werden zu überwachende Pfade je Server definiert (z. B. Freigaben, `C:\Windows\System32\drivers\etc`, Programmverzeichnisse, Konfigurationsdateien).
- Das Onboarding-Skript bzw. die GPO setzt die SACLs. Erfasst werden Ereignisse 4663/4660/4670 (Schreiben, Löschen, Berechtigungsänderung) und 5145 bei Freigaben.
- Alarme bei Änderungen an kritischen Pfaden, Massenänderungen (Ransomware-Indikator: > N Dateiänderungen/min durch einen Benutzer) und Berechtigungsänderungen.
- Grenze: Ohne Agent gibt es keine Hash-Prüfung von Dateiinhalten. Erkannt wird *wer* *was* geändert hat, nicht *wie*. Die Appliance selbst überwacht sich zusätzlich per AIDE.

### 4.5 OpenSearch

- Single Node, Security-Plugin aktiv, internes TLS, Rollen-Mapping zu Control-Plane-Rollen.
- **Indizes je Kategorie**: `siem-<kategorie>-YYYY.MM.DD`.
  - Kategorien: `firewall`, `windows`, `linux`, `network`, `edr`, `av`, `asset`, `alerts`, `audit`, `system`, `unparsed` (`ot` reserviert).
- **Codec `zstd` ab Index-Erstellung** (Template), 1 Shard, 0 Replicas.
- **ISM je Kategorie** (Retention 7–730 Tage, im UI je Kategorie; Standard 180 Tage, `audit` 365 Tage, `unparsed` 14 Tage):
  - Hot: bis Tag 7 (konfigurierbar).
  - Warm: `read_only`, `force_merge` auf 1 Segment.
  - Delete: nach Retention.
- **Speicher-Wächter** (worker):
  - OpenSearch-Watermarks: low 85 %, high 90 %, flood 95 %.
  - Warnung ab 75 %, Notbereinigung ab 85 % (älteste Indizes der Kategorien mit niedrigster Priorität zuerst; `audit` und `alerts` zuletzt), jede Löschung im Audit-Log + Alert.
  - **Retention-Plausibilisierung**: UI berechnet aus gemessenem Tagesvolumen je Kategorie den Speicherbedarf und verhindert unrealistische Einstellungen.
- Snapshots: täglich lokal (`opensearch-snapshots`), optional SMB/NFS-Ziel.

### 4.6 Switches

**Geräteprofile** (Fähigkeitsmatrix, im Code als Profil-YAML):

| Profil | Syslog | SNMPv3 Polling | Traps | Port-Matrix |
|---|---|---|---|---|
| ArubaOS-Switch | ✔ | ✔ IF-, Q-BRIDGE-, BRIDGE-, LLDP-MIB | ✔ | voll |
| FS S3900 | ✔ | ✔ IF-, Q-BRIDGE-, BRIDGE-, LLDP-MIB | ✔ | voll |
| Aruba Instant On | eingeschränkt | modell-/modusabhängig | – | reduziert (was verfügbar ist) |

- Polling alle 60 s (Status), FDB/VLAN alle 5 min.
- **LLDP-MIB** zur Uplink-/Trunk-Erkennung; Uplink-Ports werden in der Matrix gesondert dargestellt (MAC-Zählung statt Liste).
- OUI-Herstellerzuordnung über lokale IEEE-Datenbank (Kanal 1).
- **Instant On ist in Phase 4 gegen reale Hardware zu verifizieren**; Profil wird anhand der Ergebnisse finalisiert.

### 4.7 FortiGate

- **Syslog TLS 6514**, Key-Value-Format; Parser für traffic (inkl. Inter-VLAN), utm (IPS/AV/Web/App), event (Admin-Login, Konfigänderung), VPN (IPsec/SSL).
- **REST-API** (API-Token, restriktives Admin-Profil):
  - Lesen: ARP-Tabelle, DHCP-Leases, Interfaces/VLANs (für Asset-Korrelation).
  - Schreiben: nur Active Response (siehe 4.11).

### 4.8 Sophos Central

- **Primär: XDR Data Lake Query API** (OAuth2 Client Credentials, Tenant-Erkennung über Whoami/Region).
  - Zeitfenster-basierte Abfragen alle 10 min mit Überlappung + Deduplizierung über Event-ID.
  - Vorgefertigte Query-Sets (Detections, verdächtige Prozesse, Benutzer-Logons, Isolationsstatus).
  - Rate-Limits und asynchrone Query-Laufzeit werden berücksichtigt (Backoff, Job-Polling).
- **Automatischer Fallback** auf SIEM Integration API (`/siem/v1/events`, `/siem/v1/alerts`), wenn keine XDR-Lizenz/Berechtigung erkannt wird; Modus im UI sichtbar und manuell wählbar.

### 4.9 Ikarus

- Syslog-Parser für security.manager, mail.security, web.security.
- Parser werden nach Hersteller-Dokumentation erstellt und über den „Unparsed“-Workflow an realen Logs nachgeschärft.

### 4.10 Asset Discovery & ARP-Guard

**Randbedingung:** Kein Port-Mirroring/Promiscuous Mode → am Trunk sind nur Broadcasts sichtbar.

**Quellen (kombiniert):**
1. **Passiv (net-sensor)** auf `<trunk-if>.<vlan>` ohne IP (IPv6 deaktiviert, kein ARP-Reply): ARP-Requests, Gratuitous ARP, DHCP, ggf. NDP-Multicast.
2. **Switch-FDB** (SNMP): MAC ↔ Port ↔ VLAN.
3. **FortiGate-ARP-Tabelle & DHCP-Leases** (API): IP ↔ MAC je VLAN.
4. **Aktiver Discovery-Scanner** (eigene Implementierung, kein nmap): ARP-Sweep bzw. ICMP/TCP-Probes auf Top-Ports, Banner/Service-Erkennung (HTTP, SSH, SMB, RDP, SNMP-sysDescr). Läuft über das Management-Interface oder optional über explizit mit IP konfigurierte Scan-VLAN-Interfaces (bewusste Abkehr vom Stealth-Mode für dieses VLAN, im UI gekennzeichnet).

**Asset-Tabelle:** MAC, IP(s), VLAN, Switch/Port, Hersteller, Hostname, Typ, Kritikalität, first_seen, last_seen, Quelle(n).

**Alarme:**
- *New Station*: unbekannte MAC (beliebige Quelle).
- *IP/MAC-Konflikt / Spoofing-Verdacht*: IP wechselt MAC (aus Gratuitous ARP, FortiGate-ARP-Historie oder FDB-Korrelation); besonders hoch priorisiert für Gateway, DCs, Server.
- *MAC-Flapping*: MAC wechselt Switch-Port häufig.
- *Re-Appearance*: Gerät nach > X Tagen wieder aktiv.

**Discovery-Inbox**: 1-Klick-Klassifizierung (Firewall, Switch, Server, Client, Drucker, IoT, Ignorieren), MAC-Whitelist.

### 4.11 Detection Engine & Active Response

- **Eine Alert-Engine im `worker`**:
  - Sigma-Regeln werden per pySigma (OpenSearch-Backend, ECS-Pipeline) in Queries übersetzt und geplant ausgeführt (1–5 min).
  - Interne YAML-Regeln: Schwellwerte, Sequenzen, Heartbeat (Quelle > N min ohne Logs; Standard 15 min für FortiGate/DC), Asset-Alarme, Systemzustand.
  - Alerts werden in `siem-alerts-*` gespeichert und bekommen einen Status (neu, in Bearbeitung, erledigt, False Positive).
- **Regelpflege**: Kuratiertes Sigma-Set; neue/aktualisierte Regeln laufen zunächst 7 Tage im Modus „silent“, danach automatische oder manuelle Freigabe. Je Regel: aktiv/silent/aus, Ausnahmen (Feld/Wert).
- **Benachrichtigungs-Matrix** je Kategorie × Severity:
  - Kanäle: E-Mail, MS Teams (Workflows-Webhook, Adaptive Card).
  - Modi: Sofort (mit Dedupe-Key + Throttling), Digest (täglich/wöchentlich), nur Dashboard.
  - Wartungsfenster (einmalig/wiederkehrend, je Asset/Gruppe/Kategorie).
  - Empfängergruppen.
- **Active Response (FortiGate)**:
  - *Manuell*: Button „IP sperren“ an Alert/Asset/Log-Event, Dauer wählbar.
  - *Automatisch*: optional je Regel aktivierbar, nur für externe IPs per Standard.
  - Umsetzung: Adressobjekt in dedizierter Adressgruppe `SIEM_BLOCK` (vorab in Deny-Policy eingebunden, Einrichtung im Onboarding-Assistenten beschrieben) oder Quarantäne-API mit Ablaufzeit.
  - Schutzliste (nie sperren): Gateway, DCs, DNS, Appliance selbst, Management-Netze, manuell gepflegte Einträge.
  - Begrenzungen: max. Sperren/Stunde, automatische Aufhebung nach Ablaufzeit; jede Aktion → Audit-Log + Benachrichtigung.

### 4.12 KI-Bridge (optional)

- Nur externe APIs (OpenAI-kompatibel, Anthropic, Azure OpenAI); Standard **aus**.
- **Anonymizer verpflichtend**:
  - IPs, Hostnamen, Benutzernamen, E-Mail-Adressen, Domänen und MACs werden durch konsistente Platzhalter ersetzt (z. B. `HOST_07`).
  - Die Zuordnungstabelle bleibt lokal; die Antwort wird lokal zurückübersetzt.
- Funktionen: Erklärung + Handlungsempfehlung für High/Critical-Alerts, wöchentlicher Anomalie-Digest auf aggregierten Statistiken (keine Roh-Logs).
- Kosten-/Token-Limit pro Tag, Protokollierung jedes Aufrufs (ohne Inhalte) im Audit-Log.

### 4.13 Datenschutzmodus (optional aktivierbar)

- **Pseudonymisierung** von `user.name`, `user.email` und optional `source.ip` (Clients) für die Rollen Analyst/Auditor:
  - Anzeige als HMAC-Pseudonym.
  - Gespeichert wird im Klartext und nur in UI und API maskiert; OpenSearch Dashboards ist für diese Rollen dann gesperrt bzw. erhält Field-Masking über das Security-Plugin.
- **Aufdeckung** nur mit Begründung + Freigabe durch zweiten Admin (Vier-Augen), protokolliert.
- **Vier-Augen-Prinzip für Events, Alarme und Archiv** – **optional, ab Werk deaktiviert**. Es wird global eingeschaltet und gilt dann je Log-Kategorie. Ist es aus, gelten ausschließlich die Rollenrechte.
  - Der Zugriff auf Roh-Events geschützter Kategorien (z. B. `windows`, `firewall` mit Benutzerbezug) erfordert einen Antrag mit Zweck, Zeitraum und Filter. Ein zweiter berechtigter Benutzer (z. B. Datenschutzbeauftragter oder Betriebsrat) gibt ihn frei.
  - Die Freigabe ist zeitlich begrenzt (Standard 8 h) und auf den beantragten Filter beschränkt.
  - Dasselbe gilt für Archiv-Wiederherstellung, Exporte und das Löschen bzw. Schließen von Alarmen der Severity Critical.
  - Jeder Schritt (Antrag, Freigabe, Ablehnung, Zugriff) landet im Audit-Log und kann als Report ausgegeben werden.
  - Aggregierte Dashboards und Alarme ohne Personenbezug bleiben ohne Freigabe sichtbar, damit der Sicherheitsbetrieb nicht blockiert wird.
- Retention je Kategorie (4.5), Löschprotokoll.
- Exportierbare Vorlagen:
  - Verarbeitungsverzeichnis (Art. 30 DSGVO),
  - Löschkonzept,
  - Muster-Betriebsvereinbarung (Anlage technische Beschreibung).

### 4.14a Revisionssichere Archivierung & Langzeitarchiv

Unabhängig vom Such-Index (OpenSearch) wird ein **unveränderliches Rohdaten-Archiv** geführt:
- Vector schreibt jedes Event zusätzlich als Original + ECS-JSON in stündliche Archiv-Dateien (`archive/<kategorie>/YYYY/MM/DD/HH.jsonl.zst`).
- **Versiegelung** je Datei, stündlich:
  - SHA-256-Hash, verkettet mit dem Hash der vorherigen Datei (Hash-Kette je Kategorie),
  - Ed25519-Signatur mit einem appliance-eigenen Archiv-Schlüssel,
  - optional ein qualifizierter **RFC-3161-Zeitstempel** (konfigurierbarer TSA, z. B. DFN oder eine kommerzielle TSA).
- Die **Integritätsprüfung** läuft täglich automatisch und ist auf Knopfdruck auch für einen Zeitraum möglich. Fehlt eine Datei oder ist sie verändert, gibt es einen Critical-Alert. Der Prüfbericht ist als PDF exportierbar (Nachweis für Revision/Gericht).
- **Archiv-Retention** je Kategorie unabhängig vom Such-Index einstellbar (z. B. Index 90 Tage, Archiv 2 Jahre auf externem Ziel).
- **Langzeitarchiv (extern)**: Versiegelte Dateien werden täglich auf ein externes Ziel repliziert:
  - SMB/CIFS, NFS, SFTP oder S3-kompatibel (inklusive **S3 Object Lock / WORM**, z. B. MinIO, NetApp, Wasabi),
  - Zustellung verifiziert durch Hash-Vergleich, lokale Bereinigung erst nach bestätigter Replikation.
- **Wiederherstellung**: Archiv-Zeitraum auswählen, Integrität wird geprüft, Daten werden in einen temporären Index `siem-restore-*` mit Ablaufdatum eingespielt. Der Vorgang unterliegt dem Vier-Augen-Prinzip, falls aktiviert.

### 4.14b Reporting

- **Report-Engine** im `worker`: Vorlagen (Jinja2) → HTML/PDF (WeasyPrint) und CSV.
- **Zeitplan** täglich, wöchentlich, monatlich oder quartalsweise, Versand per E-Mail an Empfängergruppen; Ablage im UI mit Historie.
- **Mitgelieferte Vorlagen**:
  - Management-Summary (Sicherheitslage, Trends, offene Risiken, Ampel)
  - Anmeldungen: fehlgeschlagene Logons, Sperrungen, Logons außerhalb der Geschäftszeit, privilegierte Anmeldungen
  - Konten- & Gruppenänderungen, privilegierte Gruppen
  - AD-/GPO-Change-Report, Server-Change-Report
  - File-Integrity-Report (Änderungen an überwachten Pfaden)
  - Firewall: Top-Blocks, Top-Talker, Inter-VLAN-Verkehr, Admin-Logins, Konfigänderungen
  - VPN-Nutzung (Benutzer, Dauer, Herkunftsland)
  - AV/EDR: Detections, betroffene Hosts, Isolationen
  - Assets: neue Geräte, verschwundene Geräte, Konflikte
  - Quellen-Verfügbarkeit & Datenvollständigkeit (Heartbeat-Statistik)
  - Archiv-Integritätsnachweis
  - Vier-Augen-/Zugriffsprotokoll (für Datenschutz/Betriebsrat)
  - **Compliance-Mapping**: NIS2 (Art. 21), ISO/IEC 27001:2022 Annex A (8.15 Logging, 8.16 Monitoring), DSGVO Art. 32. Jeder Report-Abschnitt ist dem Kontroll-Ziel zugeordnet.
- Eigene Reports: Speichern einer Log-Explorer-Suche mit Aggregation als Report-Baustein.
- Reports unterliegen den Datenbereichen der Rolle des Empfängers bzw. werden im Datenschutzmodus pseudonymisiert.

### 4.14 Update-Architektur

**Kanal 1 – Content (täglich, automatisch, Hot-Reload):** Sigma-Set, IOC-Feeds (abuse.ch Feodo Tracker, URLhaus, ThreatFox; erweiterbar), IEEE-OUI, GeoIP-frei (DB-IP Lite optional). Signiert (Ed25519), atomar ausgetauscht.

**Kanal 2 – Releases (`siem-hostd update`):**
1. `release.json` + Signatur laden.
2. Ed25519-Signaturprüfung, Prüfung Versionsnummer > installiert (Downgrade-Schutz), Ablaufdatum.
3. Manifest enthält **Image-Digests**; Pull nur per Digest.
4. Pre-Update-Backup: Config-DB (SQLite Online-Backup), `/opt/siem/app`, Secrets (verschlüsselt); OpenSearch-Snapshot, falls OpenSearch-Version sich ändert.
5. Neues `app/` in Versionsverzeichnis entpacken, Symlink-Wechsel.
6. Alembic-Migration.
7. Neustart, Healthcheck (alle Dienste healthy, Ingest-Testevent Ende-zu-Ende) innerhalb 120 s.
8. Bei Fehler: Symlink zurück, Config-DB aus Backup, Images alt → Neustart.

- Modi im UI: Auto (Stable, im Wartungsfenster), Manuell, Kanal Stable/Beta.
- Release-Signing-Key offline beim Dienstleister; mehrere öffentliche Schlüssel für Rotation.
- Proxy-Unterstützung für alle Downloads.

---

## 5. Control-Plane & Web-UI

### 5.1 Sicherheit (ASVS L2)

- TLS 1.3 (eigene Root-CA, optional eigenes Zertifikat), HSTS, strikte CSP (keine Inline-Skripte), CSRF-Schutz (SameSite=Strict + Token), Cookie-Session (HttpOnly, Secure), keine Tokens im LocalStorage.
- ModSecurity CRS 4 (Paranoia Level 1, für API-Pfade 2), **Ausnahmen für Such-Endpunkte** (Log-Suche darf Angriffs-Strings enthalten), getestet mit CRS-Regression.
- Pydantic-Validierung aller Eingaben, keine Shell-Aufrufe aus der API.
- **Nur lokale Benutzer**: Argon2id, Passwort-Richtlinie, Account-Sperre/Backoff, **TOTP-MFA** (für System-Admin verpflichtend), Session-Timeout.
- **Rollenkonzept**:
  - Vordefinierte Rollen: System-Admin, Security-Analyst, Auditor (read-only), Datenschutzbeauftragter/Betriebsrat (nur Freigaben + Zugriffsprotokoll + Reports), Report-Empfänger (nur Reports).
  - **Eigene Rollen** aus granularen Berechtigungen (Modul × Lesen/Schreiben/Freigeben) und **Datenbereichen** (erlaubte Log-Kategorien, Asset-Gruppen, Feld-Maskierung).
  - Rechte gelten konsistent für UI, API, Reports und OpenSearch Dashboards (Rollen-Mapping im Security-Plugin, Document- und Field-Level-Security).
- **Audit-Log**:
  - Hash-verkettet in der Config-DB und zusätzlich in `siem-audit-*` (read-only Index).
  - Tägliche Integritätsprüfung, Manipulation → Alert.
- Secrets (SNMP, API-Keys, SMTP, Teams-URL, KI-Key) mit AES-GCM verschlüsselt; Master-Key in `data/secrets` (root, 0600).

### 5.2 Module

1. **Dashboard**: Ampelstatus aller Quellen (inkl. Heartbeat), offene Alerts nach Severity, Firewall-Blocks, EPS je Quelle, Speicher-/Systemzustand.
2. **Alerts**: Liste, Detail mit Kontext-Events, Status-Workflow, Kommentar, KI-Erklärung, Active-Response-Button.
3. **Log-Explorer**:
   - Schnellsuche (Freitext + Feldfilter, Zeitbereich, Facetten, Kontext ±N Events).
   - „In Dashboards öffnen“ für Tiefenanalyse (OpenSearch Dashboards mit SSO).
4. **Switch-Port-Matrix**: je Switch Ports mit Link, Speed, VLANs (untagged/tagged), MACs + Hersteller, Uplink-Kennzeichnung.
5. **Assets & ARP-Guard**: Live-Liste, Discovery-Inbox, Konflikt-Historie, Whitelist, Scan-Planung.
6. **Quellen & Onboarding**: Assistenten für FortiGate, Switches, Windows (WEF), Sophos, Ikarus; Status je Quelle; Bereich „Unparsed“.
7. **Regeln & Benachrichtigung**: Regelverwaltung, **Import/Export von Regeln** (Sigma-YAML und internes Format, Paket mit Abhängigkeiten, Versionsvergleich), Alert-Matrix, Wartungsfenster, Empfänger, Kanäle (SMTP, Teams).
8. **Change-Audit & FIM**: Change-Timeline je AD-Objekt/Benutzer/Server, überwachte Pfade, Hardening-Report (Audit-Policy-Check).
9. **Reports**: Vorlagen, Zeitpläne, Empfänger, Historie, Ad-hoc-Erstellung.
10. **Archiv**: Archivstatus je Kategorie, Langzeitarchiv-Ziele, Integritätsprüfung & Nachweis, Wiederherstellung.
11. **Datenschutz & Retention**: Retention je Kategorie (Index und Archiv) mit Speicherprognose, Datenschutzmodus, Vier-Augen-Anträge & Freigaben, Zugriffsprotokoll, Vorlagen-Export.
12. **System**: Firewall-Allowlists, Netzwerk/VLAN-Trunk, NTP, Proxy, Zertifikate, KI-Konfiguration, Updates & Rollback, Backup/Restore, Benutzer & Rollen, Audit-Log, **System-Protokoll** (Dienst-Logs, Ingest-Fehler, Update-Historie, Content-Updates – filterbar und exportierbar).

**Mehrsprachigkeit**: UI, E-Mails, Teams-Karten und Reports in **Deutsch und Englisch** (react-i18next bzw. Babel-Kataloge), Sprache je Benutzer bzw. je Empfängergruppe. Keine hartcodierten Texte (CI-Prüfung).

### 5.2a Betriebsfunktionen (ergänzt in 2.3.0, aus dem Handbuch abgeleitet)

- **Einrichtungsassistent** beim ersten Login: Kanäle, Firewall-Allowlists, Zertifikat, Update-Modus, erste Quellen.
- **Support-Export**: Archiv mit Versionen, Konfiguration ohne Geheimnisse, Dienstprotokollen, Prüfergebnissen.
- **Quellen-Diagnose**: eingehende Verbindungen/Pakete je Quelle der letzten Minuten, Parser-Status, Datenmenge je Quelle.
- **Health-Endpunkt** `GET /health` (ohne Anmeldung, ohne Detailinformationen) für externes Monitoring.
- **Backup**: geplant (Standard täglich), Ziele lokal + SMB/NFS/SFTP/S3, Generationen, **Backup-Kennwort** (Pflicht; verschlüsselt Schlüssel und Secrets im Backup). Wiederherstellung nach Totalausfall: frische VM → `install.sh` → Restore im Web-UI (gleicher FQDN/IP).
- **Speicher erweitern** online (LVM) per Web-UI bzw. `siem-hostd system storage-grow`.
- **SSH-Schlüsselverwaltung** im Web-UI für `siemadmin` (über `siem-hostd`).
- **`siem-hostd`-Kommandozeile** für SSH-Wartung: `system status|storage-grow`, `update check|apply|rollback`, `backup create`, `firewall show`.
- **Versionshistorie** mit Release Notes im UI. Vor manuellen Updates werden die Release Notes inklusive Verhaltensänderungen und Upgrade-Hinweisen angezeigt.
- **Kennwortrichtlinie** (≥ 12 Zeichen, Prüfung gegen kompromittierte Kennwörter, progressive Sperre), Sitzungs-Timeout 30 min (einstellbar).
- **Archiv-Wiederherstellung** in temporären Index mit Ablauf (Standard 14 Tage).
- `install.sh` Option `--proxy-ca` für Proxys mit TLS-Inspection.

### 5.3 Selbstüberwachung

Alerts bei: Dienst unhealthy, Vector-Buffer > 50 %, OpenSearch-Status ≠ green/yellow, Ingest-Latenz > 5 min, Speicher, Zertifikatsablauf (< 30 Tage), fehlgeschlagene Updates/Content-Updates, AIDE-Abweichung, SMTP-/Teams-Zustellfehler (Fallback auf jeweils anderen Kanal), Zeitdrift > 2 s.

---

## 6. Build, Test & Auslieferung

- **Auslieferung**: ausschließlich das Installationspaket `siem-installer-<version>.tar.gz` (Skript, Host-Komponenten, App-Bundle, signiertes Manifest mit Image-Digests). Container-Images werden während der Installation aus der Registry geladen. **Keine** `.ova`/`.vhdx`-Vorlagen, kein Packer.
- **Installationstests in der CI**: Jede Version wird automatisch auf frischen Debian-13-Minimal-VMs installiert (z. B. per libvirt/QEMU mit Debian-Cloud-Image): Varianten mit/ohne zweite Disk, mit/ohne Proxy, interaktiv simuliert und per Antwortdatei, zusätzlich `--repair` auf bestehender Installation und Update von der Vorversion. Abnahme durch den Selbsttest des Skripts.
- **Ersteinrichtung**: Fragen zur Installation stellt `install.sh`. Alles Weitere erfolgt im Web-UI (Einrichtungsassistent beim ersten Login: SMTP/Teams, Firewall-Allowlists, erste Quellen).
- **CI**: Lint/Typecheck, Unit-Tests, VRL-Parser-Tests (Fixtures je Hersteller), Sigma-Konvertierungstests, Integrationstest per docker compose, ZAP-Baseline-Scan, Trivy-Image-Scan, SBOM (Syft), Lizenzprüfung.
- **Testlabor**: Log-Generatoren je Quelle (aus Herstellerdoku), mindestens eine reale FortiGate, ArubaOS-Switch, Instant-On-Switch, FS S3900, Windows-Domäne (DC + Member-Server).
- **Lizenz-Compliance**: Third-Party-Notices im UI, Sigma DRL-Attribution, GPL-Quellen-Angebot.

---

## 7. Entwicklungsphasen & Abnahmekriterien

### Phase 0 – Fundament
Repository, CI-Pipeline, Test-VM-Umgebung für Installationstests (frische Debian-13-VMs), Grundgerüst `install.sh` (Preflight, Abfragen, Zustandsverwaltung, Logging), Testlabor-Generatoren.
- ✅ CI läuft grün für ein leeres Skelett.
- ✅ `install.sh --preflight` erkennt auf einer frischen Debian-13-VM korrekt erfüllte und bewusst verletzte Voraussetzungen (zu wenig RAM, kein Internet, falsche Debian-Version) und ändert nichts am System.

### Phase 1 – Host & Datenbasis
`install.sh`, nftables, `siem-hostd` (firewall, system), docker-compose mit OpenSearch (Templates, ISM je Kategorie, Security-Plugin), Vector (Syslog → generischer Parser), Proxy.
- ✅ `install.sh` installiert auf einer frischen Debian-13-Minimal-VM mit SSH ohne manuelle Zwischenschritte ein funktionsfähiges System (interaktiv und per Antwortdatei, mit und ohne zweite Disk, mit und ohne Proxy).
- ✅ Abbruch in jedem Schritt + `--resume` führt zum gleichen Ergebnis wie ein ununterbrochener Lauf; ein zweiter Lauf (`--repair`) ändert nichts an einem korrekten System.
- ✅ Kein Aussperren: Ohne hinterlegten SSH-Key bleibt die Passwort-Anmeldung aktiv; die laufende SSH-Sitzung übersteht die Installation.
- ✅ Lynis-Hardening-Index ≥ 80.
- ✅ Syslog-Testevent erscheint < 10 s in OpenSearch.
- ✅ nftables blockiert nicht freigegebene Quellen auch für Syslog/WEF (nachgewiesen per Test).
- ✅ Dead-Man's-Switch setzt Regeln nach 60 s zurück.
- ✅ Container-Neustart von Vector verliert keine TCP-Syslog-Events.

### Phase 2 – Control-Plane & Auth
FastAPI, SQLite/Alembic, lokale Benutzer, RBAC, TOTP, Audit-Log (Hash-Kette), Secrets-Verschlüsselung, React-Grundgerüst (Login, Dashboard-Layout, System-Modul Basis, i18n DE/EN von Beginn an), SSO zu OpenSearch Dashboards, System-Protokoll.
- ✅ ZAP-Baseline ohne High/Medium.
- ✅ Rollen-Matrix per automatisierten Tests abgedeckt.
- ✅ Audit-Manipulation wird erkannt.

### Phase 3 – Ingest & Parser
VRL-Parser FortiGate, ArubaOS, Instant On, FS S3900, Windows, Linux, Ikarus; Linux-Onboarding; Change-Auditing & FIM inkl. Audit-Policy-Check; OpenWEC + Onboarding-Assistent (PowerShell-Skript, Keytab-Upload, Subscriptions); Sophos (Data Lake + Fallback); Config-Generator; „Unparsed“-Bereich; Retention je Kategorie.
- ✅ Je Parser ≥ 95 % der Fixture-Events ECS-konform (Schema-Validierung).
- ✅ Windows-Server erscheint nach Skriptausführung + GPO-Update ohne weitere Handarbeit.
- ✅ Sophos-Fallback greift automatisch ohne XDR-Lizenz.
- ✅ Linux-Server (Debian, RHEL-Familie) liefert nach Einspielen des Snippets SSH-/sudo-Events.
- ✅ Change-Auditing: Gruppenmitgliedschaft, GPO-Änderung und AD-Attributänderung erscheinen korrekt in der Change-Timeline (alt → neu).
- ✅ FIM: Änderung an überwachtem Pfad erzeugt Event mit Benutzer und Prozess; Massenänderung löst Alert aus.
- ✅ Audit-Policy-Check meldet bewusst falsch konfigurierten Testserver korrekt.

### Phase 4 – Netzwerk-Sensoren
SNMPv3-Poller + Traps, Geräteprofile, Switch-Port-Matrix, FortiGate-API-Korrelation, net-sensor (VLAN-Trunk, passiv), Discovery-Scanner, Asset-Center.
- ✅ Port-Matrix für ArubaOS-Switch und FS S3900 vollständig korrekt gegenüber CLI-Ausgabe.
- ✅ Instant-On-Profil anhand realer Hardware dokumentiert.
- ✅ Simulierter IP/MAC-Wechsel (Gratuitous ARP und FortiGate-ARP-Wechsel) erzeugt Alert < 2 min.
- ✅ Sub-Interfaces haben weder IPv4 noch IPv6 und antworten auf nichts.

### Phase 5 – Detection, Alerting, Active Response, KI
Alert-Engine (Sigma + intern), Regel-Import/-Export, Report-Engine mit allen Vorlagen, Matrix, Throttling, Digest, Wartungsfenster, SMTP + Teams, Active Response FortiGate, KI-Bridge mit Anonymizer, Selbstüberwachung.
- ✅ 100 Identical Events → 1 Sofort-Benachrichtigung (Throttling).
- ✅ Heartbeat-Alert nach 15 min Stille.
- ✅ Schutzliste verhindert Sperre geschützter IPs; Sperre läuft automatisch ab.
- ✅ KI-Request enthält nachweislich keine Klartext-IPs/Hostnamen/Benutzernamen.
- ✅ Alle mitgelieferten Report-Vorlagen erzeugen PDF und CSV in DE und EN; geplanter Versand funktioniert.
- ✅ Regel-Export → Import auf zweiter Appliance ergibt identisches Regelwerk.

### Phase 6 – Updater, Datenschutz, Release
`siem-hostd update` (Signatur, Digests, Downgrade-Schutz, Rollback), Content-Kanal, Backup/Restore, revisionssicheres Archiv + Langzeitarchiv + Wiederherstellung, Datenschutzmodus inkl. Vier-Augen-Prinzip für Events/Alarme/Archiv und Vorlagen, granulare Rollen, Einrichtungsassistent im Web-UI, Dokumentation (Admin-Handbuch, Onboarding-Anleitungen je Gerät).
- ✅ Manipulation eines einzelnen Bytes in einer Archiv-Datei wird von der Integritätsprüfung erkannt und lokalisiert.
- ✅ Replikation auf S3 mit Object Lock und auf SMB funktioniert; lokale Bereinigung erst nach Verifikation.
- ✅ Archiv-Wiederherstellung eines Tages ist durchsuchbar und läuft automatisch ab.
- ✅ Vier-Augen: Zugriff ohne Freigabe wird in UI, API und Dashboards verweigert; Freigabe läuft nach Ablauf ab.
- ✅ Eigene Rolle mit eingeschränkten Kategorien sieht in UI, API, Reports und Dashboards ausschließlich diese Kategorien.
- ✅ Absichtlich fehlerhaftes Release wird automatisch zurückgerollt, ohne Datenverlust.
- ✅ Manipulierte Signatur oder älteres Release wird abgelehnt.
- ✅ 72-h-Dauertest mit 300 EPS ohne Event-Verlust, RAM stabil.

---

## 8. Entscheidungsprotokoll (ADR)

| # | Entscheidung | Begründung |
|---|---|---|
| ADR-01 | Debian 13 | Debian 12 nur noch LTS |
| ADR-02 | ECS als einziges Schema | Sigma-/pySigma-Mappings, Ökosystem |
| ADR-03 | Eigene Alert-Engine statt ElastAlert2/Security Analytics | Ein Ort für Korrelation, Throttling, Matrix, Wartungsfenster |
| ADR-04 | Hybrid-Log-Explorer mit OpenSearch Dashboards | Ausgereifte Tiefenanalyse ohne Nachbau, eigenes UI für Workflows |
| ADR-05 | Eigener Discovery-Scanner statt nmap | NPSL erlaubt keine Mitlieferung in nicht-offenen Produkten ohne OEM-Lizenz |
| ADR-06 | ARP-Guard mit FDB- und FortiGate-Korrelation | Kein Port-Mirroring möglich |
| ADR-07 | Host-Netzwerk für Ingest-Container | nftables-Regeln greifen zuverlässig |
| ADR-08 | SQLite (WAL) | Ausreichend, ein Dienst weniger |
| ADR-09 | `siem-hostd` als einzige privilegierte Schnittstelle | Kein Docker-Socket im Container, Allowlist |
| ADR-10 | Kerberos/5985 als WEF-Standard | Einfachstes Onboarding in AD-Umgebungen |
| ADR-11 | nginx + ModSecurity v3 + CRS 4 | Etabliert, CRS-Tuning gut dokumentiert |
| ADR-12 | Nur externe KI, Anonymizer verpflichtend | Ressourcen der Appliance, Datenschutz |
| ADR-13 | Image-Digest-Pinning im signierten Manifest | Signatur schützt sonst nicht vor Registry-Manipulation |
| ADR-14 | Rollback via Backup-Restore statt Alembic-Downgrade | Zuverlässiger |
| ADR-15 | Teams über Workflows-Webhook | Office-365-Connectoren abgekündigt |
| ADR-16 | Archiv getrennt vom Such-Index (Dateien + Hash-Kette + Signatur) | Revisionssicherheit unabhängig von OpenSearch; Index ist Arbeitskopie, Archiv ist Beweismittel |
| ADR-17 | FIM und Change-Auditing agentlos über Windows-Auditing | Vorgabe „keine Agenten“; Inhalts-Hashing bewusst ausgeklammert |
| ADR-18 | Report-Engine mit WeasyPrint | Open Source, PDF ohne Browser-Abhängigkeit |
| ADR-19 | Rechte konsistent bis in OpenSearch (DLS/FLS) | Sonst Umgehung von Rollen und Vier-Augen über Dashboards |
| ADR-20 | Auslieferung ausschließlich per `install.sh` auf frischer Debian-13-VM, keine OVA/VHDX | Kundenvorgabe; hypervisorunabhängig, kleinere Artefakte, kein Image-Build; Reparatur und Nachhärtung über denselben Weg (`--repair`) |

---

## 8a. Abgleich mit iQSol LogApp (Referenzprodukt)

| LogApp-Funktion | Umsetzung hier |
|---|---|
| Virtuelle Appliance | ✔ als Installation per `install.sh` auf beliebiger Debian-13-VM (keine Vorlage) |
| Manipulationssichere/revisionssichere Archivierung, Long Term Archive | ✔ 4.14a |
| LogAgents Windows/Linux | ✔ **agentlos** gleichwertig für Event-Logs (WEF, rsyslog/journald) |
| Windows-Clients | ✔ optional per WEF |
| Flatfiles (XML, CSV, …) per Agent | ✘ bewusst nicht (agentlos nicht möglich) |
| File-Integrity-Monitoring | ✔ agentlos per SACL (ohne Inhalts-Hash), 4.4b |
| Windows-Change-Auditing | ✔ 4.4b |
| Buffer, verschlüsselte Übertragung | ✔ Vector-Disk-Buffer, TLS/Kerberos |
| Syslog- und SNMP-Anbindung | ✔ |
| Syslog-/SNMP-Proxy, Kaskadierung | ✘ derzeit nicht benötigt – Roadmap (Abschnitt 10) |
| Alarmierung E-Mail, SMS/Voice | ✔ E-Mail + Teams; SMS/Voice bewusst nicht |
| Umfassendes Reporting | ✔ 4.14b inkl. NIS2/ISO-27001-Mapping |
| Vier-Augen-Prinzip für Events und Alarme (online und Archiv) | ✔ 4.13 |
| Umfangreiches Rollenkonzept | ✔ 5.1 |
| AD-Anbindung der Benutzerverwaltung | ✘ Entscheidung: nur lokale Benutzer |
| Filter-/Suchfunktion Alarme & Events | ✔ Log-Explorer + Dashboards |
| Import/Export von Regeln | ✔ 5.2 |
| Dashboard mit Systeminfos und Reports | ✔ |
| Ausführliches System-Protokoll | ✔ 5.2 |
| Mandantenfähigkeit | ✘ nicht nötig (eine Appliance je Kunde) |
| Mehrsprachigkeit | ✔ DE/EN |
| OT-SIEM | ✘ nicht in dieser Version – Roadmap (Abschnitt 10) |
| Windows-Hardening mit Bordmitteln als Projektstart | ✔ Audit-Policy-Check + GPO |
| **Darüber hinaus** | Switch-Port-Matrix, ARP-Guard/Asset-Discovery, Sophos XDR, Active Response, Sigma-Detection, KI-Bridge, signierte Auto-Updates |

---

## 9. Offene Punkte & Risiken

| # | Punkt | Maßnahme |
|---|---|---|
| R-01 | Aruba Instant On: Umfang SNMP/Syslog unklar | Verifikation mit realer Hardware in Phase 4 |
| R-02 | Keine Beispiel-Logs | Parser nach Herstellerdoku, „Unparsed“-Workflow, Testlabor |
| R-03 | FortiGate-Traffic-Logs können Volumen vervielfachen | Volumenmessung je Quelle, Empfehlung Logging-Profile im Onboarding |
| R-04 | Sophos Data Lake: Rate-Limits/Latenz | Backoff, Fallback, Monitoring |
| R-05 | Lizenz-Compliance (GPL, DRL) | Third-Party-Notices, Quellen-Angebot; rechtliche Prüfung empfohlen |
| R-06 | Active Response kann Betrieb stören | Schutzliste, Limits, Ablaufzeit, Standard aus |
| R-07 | FIM per SACL (4663) kann sehr viele Events erzeugen | Nur gezielte Pfade und nur Schreib-/Lösch-/Rechte-Zugriffe; Volumenprognose und Drosselung im UI |
| R-08 | Vier-Augen-Prinzip kann Incident-Response verzögern | „Notfallzugriff“ (Break-Glass) mit Pflichtbegründung, sofortiger Benachrichtigung aller Freigeber und nachträglicher Prüfung |
| R-09 | Umfang wächst deutlich (Reporting, Archiv, Change-Audit) | Phasen-Abnahmekriterien strikt einhalten; Reports iterativ erweitern |
| R-10 | Uneinheitliche Ausgangs-VMs (Partitionierung, Zusatzpakete, Netzwerk) | Strenger Preflight, klare Anleitung zur VM-Vorbereitung, CI-Tests mit mehreren Varianten |
| R-11 | Installation benötigt Internet (Docker-Repo, Registry) | Proxy-Unterstützung; Erreichbarkeit im Preflight geprüft |

---

## 10. Roadmap (nicht Bestandteil dieser Version)

Diese Erweiterungen sind fachlich bestätigt, werden aber erst später umgesetzt. Die Architektur dieser Version darf sie **nicht verbauen**.

### 10.1 OT-Umgebungen (bei Kunden vorhanden)

- Passives OT-Monitoring (Modbus/TCP, S7comm, OPC UA, EtherNet/IP, PROFINET-DCP), z. B. über einen Zeek-basierten Sensor an einem SPAN-Port im OT-Netz.
- OT-Asset-Inventar (SPS, HMI, RTU, Firmware-Stände), Erkennung von Programmänderungen und Schreibzugriffen.
- Zonen-Modell nach IEC 62443 / Purdue, Trennung IT- und OT-Alarmierung.

**Vorkehrungen bereits in dieser Version:**
- Die Log-Kategorien sind erweiterbar; `ot` ist im Schema reserviert.
- Das Asset-Modell hat die Felder `zone` und `asset_class`.
- Die Sensoren sind als eigenständige Container mit einheitlicher Event-Schnittstelle (HTTP/JSON → Vector) gebaut, damit später ein OT-Sensor hinzukommen kann.

### 10.2 Kaskadierung / Außenstellen

- Eine kleine Relay-Instanz (gleiches Image, Modus `relay`): Sie nimmt Syslog, SNMP-Traps und WEF lokal an, puffert auf Disk und leitet über mTLS an die Haupt-Appliance weiter. Optional nur ausgewählte Kategorien.

**Vorkehrungen bereits in dieser Version:**
- Die Vector-Konfiguration ist in Quelle, Verarbeitung und Senke modularisiert.
- Die Herkunft eines Events wird über `observer.*` und ein eigenes Feld `siem.collector` nachvollziehbar mitgeführt.
