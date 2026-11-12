# Architecture Decision Records (ADR)

Architekturentscheidungen werden als einzelne, unveränderliche Dokumente festgehalten. Wird eine Entscheidung revidiert, entsteht eine **neue** ADR, die alte erhält den Status „Ersetzt durch ADR-NNNN“.

- Dateiname: `NNNN-kurzer-titel.md` (z. B. `0003-eigene-alert-engine.md`)
- Vorlage: [0000-vorlage.md](0000-vorlage.md)

## Übersicht

ADR-01 bis ADR-21 sind aktuell gesammelt in [SPEC.md Abschnitt 8](../spec/SPEC.md#8-entscheidungsprotokoll-adr) dokumentiert. Sie werden zu Beginn von Phase 0 in Einzeldateien überführt.

| Nr. | Titel | Status | Datum |
|---|---|---|---|
| 01 | Debian 13 | Akzeptiert | 2026-11-12 |
| 02 | ECS als einziges Schema | Akzeptiert | 2026-11-12 |
| 03 | Eigene Alert-Engine | Akzeptiert | 2026-11-12 |
| 04 | Hybrid-Log-Explorer mit OpenSearch Dashboards | Akzeptiert | 2026-11-12 |
| 05 | Eigener Discovery-Scanner statt nmap | Akzeptiert | 2026-11-12 |
| 06 | ARP-Guard mit FDB-/FortiGate-Korrelation | Akzeptiert | 2026-11-12 |
| 07 | Host-Netzwerk für Ingest-Container | Akzeptiert | 2026-11-12 |
| 08 | SQLite (WAL) | Akzeptiert | 2026-11-12 |
| 09 | `siem-hostd` als einzige privilegierte Schnittstelle | Akzeptiert | 2026-11-12 |
| 10 | Kerberos/5985 als WEF-Standard | Akzeptiert | 2026-11-12 |
| 11 | nginx + ModSecurity v3 + CRS 4 | Akzeptiert | 2026-11-12 |
| 12 | Nur externe KI, Anonymizer verpflichtend | Akzeptiert | 2026-11-12 |
| 13 | Image-Digest-Pinning | Akzeptiert | 2026-11-12 |
| 14 | Rollback via Backup-Restore | Akzeptiert | 2026-11-12 |
| 15 | Teams über Workflows-Webhook | Akzeptiert | 2026-11-12 |
| 16 | Archiv getrennt vom Such-Index | Akzeptiert | 2026-11-12 |
| 17 | FIM/Change-Auditing agentlos | Akzeptiert | 2026-11-12 |
| 18 | Report-Engine mit WeasyPrint | Akzeptiert | 2026-11-12 |
| 19 | Rechte konsistent bis in OpenSearch (DLS/FLS) | Akzeptiert | 2026-11-12 |
| 20 | Auslieferung ausschließlich per `install.sh` | Akzeptiert | 2026-11-13 |
| 21 | Updates direkt über GitHub Releases + GHCR | Akzeptiert | 2026-11-13 |
