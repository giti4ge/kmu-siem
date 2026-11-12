# Versionsvergleich Spezifikation v1.0.0 ↔ v2.3.0

Dieses Dokument erklärt **was** sich geändert hat, **warum**, und **welche Folgen** das für Entwicklung, Installation und Betrieb hat.

Legende: 🔴 Korrektur eines technischen Fehlers · 🟠 geänderte Entscheidung · 🟢 neue Funktion · ⚪ entfernt/zurückgestellt

---

## 1. Plattform & Infrastruktur

| | v1.0.0 | v2.3.0 | Grund | Folge |
|---|---|---|---|---|
| 🟠 | Debian 12 oder 13 | Debian 13 | Debian 12 ist seit Mitte 2026 nur noch im LTS-Support | Ein Zielsystem, weniger Testaufwand |
| 🔴 | 16 GB RAM, Heap 50 % (max. 8 GB) | 16 GB min./24 GB empf., Heap 4–6 GB | 8 GB Heap lassen zu wenig RAM für Page-Cache und übrige Dienste | Stabilere Suchleistung |
| 🔴 | 250–500 GB | min. 500 GB, zwei Disks (OS / Daten, LVM) | 180 Tage × 2–4 GB/Tag passen nicht in 250 GB | Daten-Disk online erweiterbar |
| 🔴 | IP-Forwarding aus, forward drop, Container-Ports veröffentlicht | Ingest-Container im Host-Netzwerk, keine Port-Publishings | Docker umgeht die INPUT-Chain; Allowlists hätten nicht gegriffen | Firewall-Regeln wirken nachweisbar |
| 🟠 | `siem-updater.py` als Host-Daemon | `siem-hostd` mit Aktions-Allowlist (Firewall, Netzwerk, Update, Backup, System) | Eine einzige, kontrollierte privilegierte Schnittstelle | Kein Docker-Socket in Containern |
| 🟢 | – | chrony/NTP, auditd, AIDE, AppArmor, Container-Härtung | Lücken in v1 | Zeitstempel verlässlich, Integrität des Hosts überwacht |
| 🟠 | Fertige Vorlage `.ova` / `.vhdx` | Ausschließlich `install.sh` auf frischer Debian-13-VM mit SSH (Preflight, Antwortdatei, Resume, Repair) | Kundenentscheidung Runde 4 | Kein Image-Build; Hypervisor beliebig; VM wird vom Techniker vorbereitet |
| 🟢 | – | CI mit automatischen Installationstests auf frischen VMs, Testlabor, SBOM, Lizenzprüfung | Reproduzierbarkeit | Phase 0 neu |

## 2. Daten & Speicherung

| | v1.0.0 | v2.3.0 | Grund | Folge |
|---|---|---|---|---|
| 🟠 | ECS oder OCSF | nur ECS | Ein Schema; Sigma-Mappings basieren auf ECS | Klare Parser-Vorgaben |
| 🟠 | Ein Index `siem-logs-*` | Ein Index je Kategorie `siem-<kategorie>-*` | Retention je Log-Typ | Retention-Einstellung je Kategorie |
| 🔴 | ZSTD erst in der Warm-Phase | ZSTD ab Index-Erstellung | `index.codec` ist statisch | Template-basiert |
| 🔴 | Warnung 80 %, Bereinigung 90 % | Warnung 75 %, Bereinigung 85 %, OpenSearch-Watermarks explizit | Bei 90 % greift bereits die OpenSearch-High-Watermark | Kein Ingest-Stopp |
| 🟠 | Retention 30–730 Tage global | 7–730 Tage je Kategorie, mit Speicherprognose | Unrealistische Werte verhindern | UI begrenzt Eingaben |
| 🟠 | SQLite oder PostgreSQL | SQLite (WAL) | Ein Dienst weniger | – |
| 🟢 | – | Revisionssicheres Archiv + externes Langzeitarchiv (S3 Object Lock, SMB, NFS, SFTP) | Abgleich LogApp | Beweissicherheit, Nachweis per PDF |
| 🟢 | – | OpenSearch-Snapshots | Rollback-Fähigkeit bei OpenSearch-Updates | – |

## 3. Datenquellen

| | v1.0.0 | v2.3.0 | Grund | Folge |
|---|---|---|---|---|
| 🟠 | WEF über 5985/5986 | Kerberos über 5985 als Standard, Assistent mit PowerShell-Skript | Einfaches Onboarding in AD-Umgebungen | Keine Zertifikate auf Servern nötig |
| 🟢 | – | Subscriptions je Rolle (DC, Exchange, Member-Server, optional Clients) | Klarer Datenumfang | – |
| 🟢 | – | Linux agentlos (rsyslog/journald) | Abgleich LogApp | – |
| 🟢 | – | Change-Auditing, agentloses FIM, Audit-Policy-Check | Abgleich LogApp | Neue UI-Module und Reports |
| 🟠 | Sophos SIEM-API | XDR Data Lake primär, automatischer Fallback | Kundenentscheidung | – |
| 🟠 | Aruba & FS allgemein | Geräteprofile ArubaOS-Switch, Instant On, FS S3900; LLDP-MIB | Fähigkeiten unterscheiden sich stark | Instant On mit reduzierter Matrix |
| 🔴 | SNMP-Traps-Port offen, aber kein Empfänger | Trap-Receiver im `snmp`-Container | Lücke | – |
| 🟢 | – | Bereich „Unparsed“ | Keine Beispiel-Logs vorhanden | Kein Datenverlust bei unbekannten Formaten |

## 4. Netzwerk-Sichtbarkeit

| | v1.0.0 | v2.3.0 | Grund | Folge |
|---|---|---|---|---|
| 🔴 | ARP-Guard rein passiv am Trunk erkennt Spoofing | Passiv + Switch-FDB + FortiGate-ARP-Tabelle | Ohne Port-Mirroring sind ARP-Replies (Unicast) unsichtbar | Spoofing-Erkennung über Korrelation |
| 🟠 | nmap | Eigener Python-Discovery-Scanner | NPSL-Lizenz ungeeignet für Mitlieferung | – |
| 🔴 | Stealth-Interfaces und nmap-Scan über dieselben VLANs | Scan über Management-Interface oder explizit gekennzeichnete Scan-Interfaces; IPv6 auf Stealth-Interfaces aus | Ohne IP kein aktiver Scan; Link-Local-Adressen | – |

## 5. Detection & Alarmierung

| | v1.0.0 | v2.3.0 | Grund | Folge |
|---|---|---|---|---|
| 🟠 | Sigma + ElastAlert2 / OpenSearch Security Analytics | Eine eigene Alert-Engine (pySigma) | Throttling, Matrix, Wartungsfenster an einer Stelle | – |
| 🟢 | – | Neue Sigma-Regeln 7 Tage „silent“ | Fehlalarme vermeiden | – |
| 🟢 | SMTP | E-Mail + MS Teams (Workflows-Webhook), gegenseitiger Fallback | Kundenentscheidung | – |
| 🟢 | – | Active Response FortiGate (manuell + optional automatisch, Schutzliste) | Kundenentscheidung | Vorbereitung auf FortiGate nötig |
| 🟠 | KI lokal (Ollama) oder extern | Nur extern, Anonymizer verpflichtend | Ressourcen, Kundenentscheidung | – |
| 🟢 | – | Report-Engine mit Vorlagen und NIS2/ISO-27001/DSGVO-Mapping | Abgleich LogApp | – |

## 6. Web-UI, Sicherheit & Datenschutz

| | v1.0.0 | v2.3.0 | Grund | Folge |
|---|---|---|---|---|
| 🟠 | „OWASP-konform“ | OWASP ASVS 4.0 Level 2 | Prüfbarer Maßstab | – |
| 🟠 | Caddy oder nginx + ModSecurity | nginx + ModSecurity v3 + CRS 4 mit Ausnahmen für die Log-Suche | Suchbegriffe würden sonst geblockt | – |
| 🟠 | Log-Explorer selbst gebaut | Hybrid: eigene Schnellsuche + OpenSearch Dashboards (SSO) | Professionelle Tiefenanalyse ohne Nachbau | – |
| 🟠 | 3 feste Rollen, MFA optional | Vordefinierte + eigene Rollen mit Datenbereichen; MFA Pflicht für Admins; nur lokale Benutzer | Abgleich LogApp, Kundenentscheidung | Rechte gelten bis in OpenSearch (DLS/FLS) |
| 🟢 | – | Datenschutzmodus, optionales Vier-Augen-Prinzip, DSGVO-/Betriebsrats-Vorlagen | Kundenentscheidung | – |
| 🟢 | – | Mehrsprachigkeit DE/EN, Regel-Import/-Export, System-Protokoll | Abgleich LogApp | – |

## 7. Updates

| | v1.0.0 | v2.3.0 | Grund | Folge |
|---|---|---|---|---|
| 🔴 | Signatur auf `release.json`, Pull per Tag | Pull per Image-Digest aus signiertem Manifest, Downgrade-Schutz, Schlüsselrotation | Signatur schützte sonst nicht vor Registry-Manipulation | – |
| 🔴 | Rollback per Alembic | Rollback per Backup-Restore, Snapshot vor OpenSearch-Update | Down-Migrationen unzuverlässig, Index-Formate nicht abwärtskompatibel | – |
| 🟠 | Healthcheck 60 s | 120 s inkl. Ende-zu-Ende-Testevent | Realistische Startzeit von OpenSearch | – |

## 8. Zurückgestellt (Roadmap)

| | Thema | Status |
|---|---|---|
| ⚪ | Kaskadierung / Relay für Außenstellen | Roadmap 10.2, Architektur vorbereitet |
| ⚪ | OT-Monitoring | Roadmap 10.1, Architektur vorbereitet |
| ⚪ | Log-Agenten, Flatfiles, Exchange Message Tracking | Bewusst nicht vorgesehen (agentlos) |
| ⚪ | AD-Anmeldung am Web-UI, SMS/Voice, Mandantenfähigkeit, lokale KI | Bewusst nicht vorgesehen (Kundenentscheidung) |

## 9. Entwicklungsphasen

| v1.0.0 | v2.3.0 |
|---|---|
| – | **Phase 0** Fundament (Repo, CI, Installationstest-Umgebung, Preflight-Grundgerüst, Testlabor) |
| Phase 1 Infrastruktur | Phase 1 Host & Datenbasis |
| Phase 2 Control-Plane & Auth | Phase 2 Control-Plane & Auth (+ i18n, System-Protokoll, SSO Dashboards) |
| Phase 3 Ingest & Parser | Phase 3 Ingest & Parser (+ Linux, Change-Audit, FIM) |
| Phase 4 Netzwerk-Sensoren | Phase 4 Netzwerk-Sensoren (+ FortiGate-Korrelation, eigener Scanner) |
| Phase 5 Alerting, KI, Updater | Phase 5 Detection, Reporting, Active Response, KI |
| – | **Phase 6** Updater, Archiv, Datenschutz, Release |

Jede Phase hat in v2 messbare Abnahmekriterien (SPEC Abschnitt 7).
