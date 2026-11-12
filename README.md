# KMU-SIEM & Network-Visibility Appliance

Gehärtete SIEM-Appliance für die zentrale Protokollierung, Erkennung von Sicherheitsvorfällen und Netzwerk-Sichtbarkeit in KMU-Umgebungen. Sie basiert ausschließlich auf Open-Source-Komponenten (Debian 13, OpenSearch, Vector, OpenWEC) und wird als Bestandteil unserer Dienstleistung beim Kunden betrieben.

**Installation:** ausschließlich über `install.sh` auf einer frischen, schlanken Debian-13-VM mit SSH. Das Skript installiert alle Abhängigkeiten, härtet das System und richtet die Anwendung ein. Es gibt keine VM-Vorlagen. Details: [Handbuch Kap. 3](docs/handbuch/03-installation.md).

> **Projektstatus:** Spezifikation 2.4.0 freigegeben (2026-11-13). Implementierung Phase 0 läuft (Produktversion: unreleased).

## Funktionsüberblick

- **Agentlose Log-Sammlung**: FortiGate, ArubaOS-Switch, Aruba Instant On, FS S3900, Windows (WEF/Kerberos), Linux (rsyslog/journald), Sophos Central (XDR Data Lake), Ikarus
- **Erkennung**: Sigma-Regeln, Korrelation, Heartbeat-Überwachung, Threat-Intel-Abgleich
- **Alarmierung**: E-Mail und MS Teams mit Matrix je Kategorie × Severity, Throttling, Digest, Wartungsfenster
- **Netzwerk-Sichtbarkeit**: Switch-Port-Matrix, Asset-Discovery, ARP-Guard
- **Active Response**: IP-Sperre auf der FortiGate (manuell oder regelbasiert)
- **Compliance**: Change-Auditing, agentloses File-Integrity-Monitoring, revisionssicheres Archiv, Reports (NIS2, ISO 27001, DSGVO)
- **Datenschutz**: Retention je Kategorie, optionaler Datenschutzmodus und Vier-Augen-Prinzip
- **Betrieb**: Web-UI für die gesamte Konfiguration, signierte Updates direkt über GitHub (Releases + Container Registry) mit automatischem Rollback

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [docs/README.md](docs/README.md) | Einstieg und Übersicht aller Dokumente |
| [docs/spec/SPEC.md](docs/spec/SPEC.md) | Gültige Master-Spezifikation |
| [docs/handbuch/](docs/handbuch/README.md) | Betriebs- und Administrationshandbuch |
| [docs/VERSIONIERUNG.md](docs/VERSIONIERUNG.md) | Versionierung, Release-Kanäle, Upgrade-Pfade |
| [CHANGELOG.md](CHANGELOG.md) | Änderungen je Version |

## Repository-Struktur

```
.
├── CHANGELOG.md
├── README.md
└── docs/
    ├── VERSIONIERUNG.md
    ├── spec/            Spezifikation (aktuell, eingefroren, Historie, Vergleich)
    ├── adr/             Architecture Decision Records
    ├── handbuch/        Betriebshandbuch
    └── release-notes/   Upgrade-Hinweise je Version
```

Code-Verzeichnisse (`host/`, `app/`, `build/`, `tests/`) entstehen ab Phase 0.
