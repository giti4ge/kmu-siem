# 9. Betrieb & Wartung

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.4.0)

## 9.1 Updates

Die Appliance kennt drei Update-Arten:

| Art | Inhalt | Ablauf | Unterbrechung |
|---|---|---|---|
| **Betriebssystem** | Debian-Sicherheitsupdates | täglich automatisch (unattended-upgrades); Neustart nur im Reboot-Fenster | nur beim Neustart (Ereignisse über TCP/TLS werden von den Quellen bzw. dem Puffer nachgeliefert, UDP-Syslog kann verloren gehen) |
| **Content** | Sigma-Regeln, Threat-Intel, Hersteller-Datenbank, Parser-Korrekturen | täglich automatisch, signiert | keine |
| **Appliance-Release** | Neue Funktionen, Fehlerbehebungen, Komponenten | automatisch (Stable) im Wartungsfenster oder manuell | wenige Minuten, Ereignisse werden gepuffert |

### Update-Quelle GitHub

Appliance-Releases und eigene Content-Pakete kommen **direkt von GitHub**:

| Was | Woher |
|---|---|
| Versionen, Manifest, Release Notes | GitHub Releases von `giti4ge/kmu-siem-releases` |
| Container-Images | GitHub Container Registry (`ghcr.io`) |
| Content-Pakete | GitHub Releases mit Tag `content-…` |

Die Appliance prüft stündlich, ob neue Versionen vorliegen. Installiert wird im Wartungsfenster (Automatik) oder auf Klick.

> **Sicherheit:** Die Appliance installiert nur Versionen, deren Manifest mit dem **Offline-Schlüssel des Dienstleisters** signiert ist. Ein Release, das ohne gültige Signatur auf GitHub erscheint (etwa durch einen kompromittierten Zugang), wird ignoriert und als Systemalarm gemeldet.

### Einstellungen

**System → Updates**

| Einstellung | Optionen |
|---|---|
| Modus | Automatisch · Manuell |
| Kanal | Stable · Beta |
| Wartungsfenster | Wochentag und Uhrzeit (gilt auch als Reboot-Fenster für OS-Updates) |
| GitHub-Zugang | Zugangstoken (nur bei privatem Distributions-Repository), Status der letzten Abfrage, **Verbindung testen** |
| Quelle (Experten) | Repository-Name, falls das Distributions-Repository umzieht |

### Bestimmte Version installieren

**System → Updates → Verfügbare Versionen** listet alle Versionen des gewählten Kanals von GitHub mit Release Notes. Möglich sind:
- **Neueste installieren**
- **Diese Version installieren** (z. B. bewusst nicht die neueste, wenn ein Kunde erst später nachziehen soll)

Ältere Versionen als die installierte werden nicht angeboten. MAJOR-Sprünge sind nur über die vorgeschriebene Zwischenversion möglich, die Appliance zeigt den Weg an.

### Ausweichweg ohne GitHub-Zugriff

**System → Updates → Paket hochladen**: Installationspaket und Signatur von der GitHub-Release-Seite herunterladen und hochladen. Die Prüfung ist identisch. Container-Images werden in diesem Fall weiterhin von `ghcr.io` geladen.

> **Hinweis:** MAJOR-Versionen (z. B. 1.x → 2.0) werden **nie** automatisch installiert. Ihre Release Notes enthalten Upgrade-Hinweise (siehe [VERSIONIERUNG.md](../VERSIONIERUNG.md)).

### Ablauf eines Appliance-Updates

1. Manifest laden, **Signatur** und Versionsnummer prüfen (keine Downgrades).
2. Prüfen, ob von der installierten Version direkt aktualisiert werden darf.
3. Sicherung: Konfiguration, Anwendung, Schlüssel. Bei neuer OpenSearch-Version zusätzlich ein Snapshot.
4. Container-Images per Digest laden.
5. Neue Version aktivieren, Datenbank migrieren, Dienste neu starten.
6. **Selbsttest** (alle Dienste, Test-Ereignis) innerhalb von 120 Sekunden.
7. Bei Fehler: **automatischer Rollback** auf die vorherige Version mit Benachrichtigung.

### Was hat sich geändert?

**System → Updates → Versionshistorie** zeigt installierte Versionen mit Datum, Ergebnis und Link zu den Release Notes. Vor einem manuellen Update werden die Release Notes der neuen Version angezeigt, inklusive *Änderungen im Verhalten* und *Upgrade-Hinweisen*.

### Manuelles Zurücksetzen

**System → Updates → Auf vorherige Version zurücksetzen**: Nur unmittelbar nach einem Update und nur auf die direkte Vorgängerversion. Konfigurationsänderungen seit dem Update gehen dabei verloren (Hinweis im Dialog).

### Update per Kommandozeile (SSH)

```bash
sudo siem-hostd update check                     # GitHub abfragen
sudo siem-hostd update list                      # verfügbare Versionen des Kanals
sudo siem-hostd update apply                     # neueste Version des Kanals
sudo siem-hostd update apply --version v1.4.2    # bestimmte Version
sudo siem-hostd update rollback
sudo siem-hostd update set-token --file ~/github.token   # Zugangstoken erneuern
```

## 9.2 Backup und Wiederherstellung

### Was gesichert wird

| Inhalt | Backup | Langzeitarchiv | Snapshot |
|---|---|---|---|
| Konfiguration (Quellen, Regeln, Benutzer, Einstellungen) | ✔ | – | – |
| Zertifikate, Schlüssel (verschlüsselt mit Backup-Kennwort) | ✔ | – | – |
| Original-Ereignisse | – | ✔ | – |
| Durchsuchbarer Index | – | – | ✔ (optional) |

### Geplantes Backup

**System → Backup**: Zeitplan (Standard täglich), Ziel (lokal + SMB/NFS/SFTP/S3), Anzahl Generationen, **Backup-Kennwort** (Pflicht, verschlüsselt die Schlüssel im Backup).

> **Achtung:** Ohne das Backup-Kennwort ist eine Wiederherstellung nicht möglich. Das Kennwort außerhalb der Appliance sicher aufbewahren (z. B. im Kennwortmanager des Dienstleisters).

### Wiederherstellung nach Totalausfall

Da die Installation vollständig über das Skript erfolgt, ist die Wiederherstellung immer gleich:

1. Neue VM vorbereiten und Debian installieren (Kap. 3.4–3.5), **gleicher FQDN und gleiche IP**.
2. `install.sh` derselben oder einer neueren Version ausführen.
3. Im Web-UI: **System → Backup → Wiederherstellen**, Backup-Datei und Backup-Kennwort angeben.
4. Archiv: Langzeitarchiv-Ziel wieder verbinden. Die Archivkette wird erkannt und geprüft. Benötigte Zeiträume bei Bedarf wiederherstellen (8.7).
5. Windows-Keytab ist im Backup enthalten, die Server verbinden sich automatisch wieder.

## 9.3 Speicherverwaltung

**Dashboard → Speicher** bzw. **System → Speicher**

| Schwelle | Reaktion |
|---|---|
| 75 % | Warnung |
| 85 % | Notbereinigung: älteste Indizes der Kategorien mit niedrigster Priorität werden gelöscht (`alerts`, `audit` zuletzt), jeweils mit Alarm |
| 95 % | OpenSearch sperrt Schreibzugriffe, Ereignisse werden im Puffer gehalten (bis zu 10 GB) |

### Daten-Disk vergrößern

1. Virtuelle Disk im Hypervisor vergrößern.
2. **System → Speicher → Disk-Größe neu einlesen und erweitern** (führt die LVM-Erweiterung online aus).

Alternativ per SSH: `sudo siem-hostd system storage-grow`.

## 9.4 Selbstüberwachung

Die Appliance alarmiert selbstständig bei:

- Dienst ausgefallen oder nicht gesund
- Ereignis-Puffer mehr als 50 % gefüllt
- Verzögerung der Verarbeitung > 5 Minuten
- Speicherschwellen (9.3)
- Zertifikat läuft in < 30 Tagen ab
- Update oder Content-Update fehlgeschlagen
- Abweichung der Systemdateien (AIDE)
- Archiv-Integrität verletzt oder Replikation fehlgeschlagen
- Zustellfehler E-Mail/Teams (Meldung über den jeweils anderen Kanal)
- Zeitabweichung > 2 Sekunden

> **Hinweis:** Fällt die Appliance komplett aus, kann sie sich nicht selbst melden. Empfehlung: Die Erreichbarkeit von `https://siem.firma.local/health` durch ein vorhandenes Monitoring des Dienstleisters oder Kunden prüfen lassen.

## 9.5 Systemzustand prüfen und Nachhärten

```bash
sudo /opt/siem/host/install.sh --preflight    # Voraussetzungen
sudo /opt/siem/host/install.sh --repair       # Sollzustand wiederherstellen
sudo siem-hostd system status                 # Dienste, Speicher, Versionen
```

`--repair` ist sicher wiederholbar und verändert keine Daten. Empfohlen nach manuellen Eingriffen per SSH oder wenn die Härtungsprüfung Abweichungen meldet.

## 9.6 Regelmäßige Aufgaben (Empfehlung)

| Turnus | Aufgabe |
|---|---|
| täglich | Dashboard prüfen, neue Critical/High-Alarme bearbeiten |
| wöchentlich | Discovery-Inbox abarbeiten, Regeln „Zur Freigabe“ prüfen, Unparsed-Ereignisse sichten |
| monatlich | Management-Report besprechen, Quellen-Verfügbarkeit prüfen, Backup-Wiederherstellung stichprobenartig testen |
| quartalsweise | Benutzer und Rollen überprüfen, Ausnahmen mit Ablaufdatum prüfen, Archiv-Integritätsnachweis ablegen, Firewall-Allowlists prüfen |
| jährlich | Retention und Datenschutz-Dokumente überprüfen, Wiederherstellung nach Totalausfall üben |
