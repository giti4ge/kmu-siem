# Architecture Decision Records (ADR)

Architekturentscheidungen werden als einzelne, unveränderliche Dokumente festgehalten. Wird eine Entscheidung revidiert, entsteht eine **neue** ADR, die alte erhält den Status „Ersetzt durch ADR-NNNN“.

- Dateiname: `NNNN-kurzer-titel.md` (z. B. `0003-eigene-alert-engine.md`)
- Vorlage: [0000-vorlage.md](0000-vorlage.md)

## Übersicht

| Nr. | Titel | Status | Datum |
|---|---|---|---|
| [0001](0001-debian-13.md) | Debian 13 als einzige Basis | Akzeptiert | 2026-11-12 |
| [0002](0002-ecs-schema.md) | ECS als einziges Log-Schema | Akzeptiert | 2026-11-12 |
| [0003](0003-eigene-alert-engine.md) | Eine eigene Alert-Engine | Akzeptiert | 2026-11-12 |
| [0004](0004-hybrid-log-explorer.md) | Hybrid-Log-Explorer mit OpenSearch Dashboards | Akzeptiert | 2026-11-12 |
| [0005](0005-eigener-discovery-scanner.md) | Eigener Discovery-Scanner statt nmap | Akzeptiert | 2026-11-12 |
| [0006](0006-arp-guard-korrelation.md) | ARP-Guard mit Switch-FDB- und FortiGate-Korrelation | Akzeptiert | 2026-11-12 |
| [0007](0007-host-netzwerk-ingest.md) | Host-Netzwerk für Ingest-Container | Akzeptiert | 2026-11-12 |
| [0008](0008-sqlite.md) | SQLite (WAL) für die Konfiguration | Akzeptiert | 2026-11-12 |
| [0009](0009-siem-hostd.md) | siem-hostd als einzige privilegierte Schnittstelle | Akzeptiert | 2026-11-12 |
| [0010](0010-wef-kerberos.md) | Kerberos über 5985 als WEF-Standard | Akzeptiert | 2026-11-12 |
| [0011](0011-nginx-modsecurity.md) | nginx + ModSecurity v3 + OWASP CRS 4 | Akzeptiert | 2026-11-12 |
| [0012](0012-nur-externe-ki.md) | Nur externe KI, Anonymisierung verpflichtend | Akzeptiert | 2026-11-12 |
| [0013](0013-image-digest-pinning.md) | Image-Digest-Pinning im signierten Manifest | Akzeptiert | 2026-11-12 |
| [0014](0014-rollback-backup-restore.md) | Rollback per Backup-Restore | Akzeptiert | 2026-11-12 |
| [0015](0015-teams-workflows.md) | MS Teams über Workflows-Webhook | Akzeptiert | 2026-11-12 |
| [0016](0016-archiv-getrennt.md) | Revisionssicheres Archiv getrennt vom Such-Index | Akzeptiert | 2026-11-12 |
| [0017](0017-fim-change-agentlos.md) | FIM und Change-Auditing agentlos | Akzeptiert | 2026-11-12 |
| [0018](0018-weasyprint-reports.md) | Report-Engine mit WeasyPrint | Akzeptiert | 2026-11-12 |
| [0019](0019-rechte-dls-fls.md) | Rechte konsistent bis in OpenSearch (DLS/FLS) | Akzeptiert | 2026-11-12 |
| [0020](0020-installation-install-sh.md) | Auslieferung ausschließlich per install.sh | Akzeptiert | 2026-11-13 |
| [0021](0021-updates-github.md) | Updates direkt über GitHub Releases + GHCR | Akzeptiert | 2026-11-13 |
