# Projektstand und offene Punkte

Stand: 2026-11-14 · Bezug: [Spezifikation 2.6.1](spec/SPEC.md)

## Umgesetzt (auf main bzw. im Sammel-PR)

| Bereich | Stand |
|---|---|
| Installation, Härtung, Host-Dienst, Container-Stack | fertig (Phase 0–2), CI mit Debian-13-VM |
| Parser | FortiGate, ArubaOS, Instant On, FS S3900, Linux, Windows (OpenWEC), UniFi, Synology, iDRAC, Ikarus |
| Quellen | Syslog UDP/TCP/TLS, WEF/OpenWEC, SNMP-Traps und Polling, FortiGate-API (ARP/DHCP), Sophos Central |
| Asset-Center, Port-Matrix, Change-Timeline | fertig |
| Wartung | Plattenwächter, Sicherung der Konfigurationsdatenbank, Snapshots, Integritätsprüfung |
| Eingangsschutz | nftables-Limits je Quelle, Vector-Drossel, SNMP-Rate-Limit, Proxy-Limits |
| Rückkopplung | Probenexport (pseudonymisiert), Diagnosepaket, Betriebstagebuch |
| Alert-Engine | 16 Regeln mit MITRE-Zuordnung, Schwellwerte, Alarmverwaltung |
| Benachrichtigung | E-Mail (SMTP), Microsoft Teams (Workflows-Webhook) |
| Dashboard | Ampel je Bereich, offene Alarme, Top-Quellen, Einrichtungs-Prüfliste, Widgets je Browser anpassbar |
| KI-Bridge | Anthropic, Gemini, OpenAI-kompatibel, Azure, eigener Endpunkt; Alarm-Erklärung; Vorfallsanalyse mit Beweisbindung |
| Active Response | FortiGate-IP-Sperre manuell und automatisch (Standard aus) |
| Reports | Zusammenfassung, CSV, Druck/PDF über den Browser; Rolle Management |
| Updates | Prüfung auf neue Versionen (GitHub Releases, Kanal stable/beta) |

## Bewusst vereinfacht (Abweichung von der Spezifikation)

- **PDF-Reports:** über den Druckdialog des Browsers statt serverseitig (WeasyPrint, ADR-18).
- **Updates:** Prüfung und Anzeige; das Einspielen erfolgt mit dem signierten Paket über `install.sh --upgrade`. Kein automatischer Abruf mit Signaturprüfung im Web-UI.
- **Dashboard-Anpassung:** je Browser (lokal gespeichert), nicht je Benutzer in der Konfigurationsdatenbank.
- **Regeln:** 16 eingebaute Regeln mit Schwellwert, Schweregrad und Ein/Aus; kein Sigma-Import und keine eigenen Regeln im UI.
- **Windows-Skript:** nur per Review und Unit-Test geprüft, nicht an einer echten Domäne.

## Offen (noch nicht gebaut)

1. Support-Zugang per SSH (Issue #28) – zeitlich begrenzt, eingeschränkt.
2. Revisionssicheres Archiv (Write-once, Hash-Kette) und Fall-Verwaltung/Forensik-Export (RFC 3161).
3. Datenschutzmodus (Pseudonymisierung in der Oberfläche, Vier-Augen-Freigabe) – Schalter aus der Spezifikation 4.13.
4. Quellenfreigabe (Quarantäne unbekannter Absender mit Ein-Klick-Freigabe).
5. Phase 4 Rest: LLDP, Geräteprofile, MIB-Import, net-sensor, Discovery-Scanner.
6. Parser-Editor im Web-UI, Konfigurations-Snapshots von Geräten, Anbindungs-Assistent mit Zertifikaten.
7. Lasttest mit 150 Endpunkten und Erstinstallation mit echten Geräten (Voraussetzung für „einsatzbereit“).

## Voraussetzung für den Einsatz

Die CI belegt Installation, Konfiguration und Logik. Ob alles mit echten Geräten, Proben und Last zusammenspielt, zeigt erst die Erstinstallation; Proben stellt der Auftraggeber pseudonymisiert bereit (Rückkopplung).
