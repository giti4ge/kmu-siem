# 3. Installation

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.4.0)

> **Geändert gegenüber früheren Entwürfen:** Es gibt **keine** fertigen VM-Vorlagen (`.ova`/`.vhdx`) mehr. Die Installation inklusive aller Abhängigkeiten und der Härtung erfolgt ausschließlich über das Installationsskript `install.sh` auf einer frischen Debian-13-VM.

## 3.1 Überblick

```
VM anlegen ─► Debian 13 minimal + SSH installieren ─► Installationspaket kopieren
   ─► install.sh --preflight ─► install.sh ─► Web-UI: Einrichtungsassistent
```

Dauer: ca. 15 min für die Debian-Grundinstallation, 15–30 min für `install.sh` (abhängig von der Internetanbindung).

## 3.2 Systemanforderungen

| Ressource | Minimum | Empfohlen |
|---|---|---|
| vCPU | 4 | 6–8 |
| RAM | 16 GB (statisch, kein dynamischer Speicher/Ballooning) | 24 GB |
| Disk 1 (System) | 40 GB | 40 GB |
| Disk 2 (Daten) | 500 GB SSD, **leer, nicht partitioniert** | 750 GB–1 TB SSD/NVMe |
| Netzwerkkarte 1 | Management + Log-Empfang, feste IP | – |
| Netzwerkkarte 2 (optional) | VLAN-Trunk für ARP-Guard | – |
| Hypervisor | beliebig (VMware ESXi/vSphere, Hyper-V Gen2, Proxmox, …) | – |
| Internet | HTTPS ausgehend, direkt oder über Proxy | – |

### Speicherbedarf abschätzen

`Speicher (GB) ≈ Rohdaten pro Tag (GB) × Aufbewahrung (Tage) × 0,8 + 50 GB Reserve`

Beispiel: 3 GB/Tag × 180 Tage × 0,8 + 50 = **482 GB**. Nach einer Woche Betrieb zeigt **Datenschutz & Retention** die gemessene Prognose je Kategorie.

> **Achtung:** Thin Provisioning auf überbuchten Datastores vermeiden. Läuft der Datastore voll, stoppt die Protokollierung.

### Benötigte Internet-Ziele während der Installation

| Ziel | Zweck |
|---|---|
| `deb.debian.org`, `security.debian.org` | Debian-Pakete und Sicherheitsupdates |
| `download.docker.com` | Docker Engine |
| `github.com`, `api.github.com`, `objects.githubusercontent.com` | Installationspaket, Manifest, Content-Pakete (GitHub Releases) |
| `ghcr.io`, `pkg-containers.githubusercontent.com` | Container-Images der Appliance (GitHub Container Registry) |

> **⚠ Zu verifizieren:** Die vollständige Liste der GitHub-Download-Hosts wird bei der Implementierung gegen die aktuelle GitHub-Dokumentation abgeglichen und im Preflight geprüft.

## 3.3 Vorbereitung im Netzwerk

| Vorbereitung | Zweck |
|---|---|
| Feste IP-Adresse und DNS-Name (A-Record) `siem.firma.local` | Erreichbarkeit, Kerberos für Windows |
| Zugang zu DNS-Servern und NTP (bevorzugt DCs) | Namensauflösung, korrekte Zeit |
| Ausgehend HTTPS (siehe oben) und später zu Sophos Central, abuse.ch, IEEE, ggf. KI-Anbieter | Installation, Updates, Feeds |
| SMTP-Relay (oder M365/Exchange-Konto) | E-Mail-Alarme |
| Firewall-Regeln von den Quellen zur Appliance | siehe [Anhang A](anhang.md#a-ports) |

## 3.4 VM anlegen

### VMware ESXi / vSphere

1. Neue VM, Gastbetriebssystem **Debian GNU/Linux 12/13 (64-Bit)**, Ressourcen gemäß 3.2, zwei Festplatten (System, Daten), Netzwerkkarte(n) vom Typ VMXNET3.
2. **Optional – VLAN-Trunk für ARP-Guard** (Netzwerkkarte 2):
   - Standard-vSwitch: Portgruppe mit **VLAN-ID 4095**.
   - Distributed Switch: Portgruppe mit **VLAN-Typ „VLAN-Trunking“** und den gewünschten VLAN-Bereichen.
   - Promiscuous Mode wird **nicht** benötigt.

### Hyper-V

1. Neue VM **Generation 2**, Secure Boot mit Vorlage **„Microsoft UEFI-Zertifizierungsstelle“**, Arbeitsspeicher **statisch**.
2. Zwei virtuelle Festplatten (System, Daten), Netzwerkkarte 1 am Server-Switch.
3. **Optional – VLAN-Trunk für ARP-Guard** (auf dem Hyper-V-Host):

   ```powershell
   Add-VMNetworkAdapter -VMName "SIEM" -Name "Trunk" -SwitchName "<vSwitch>"
   Set-VMNetworkAdapterVlan -VMName "SIEM" -VMNetworkAdapterName "Trunk" `
       -Trunk -AllowedVlanIdList "10,20,30-40" -NativeVlanId 0
   ```

### Andere Hypervisoren

Entsprechend: zwei Disks, statischer RAM, für den Trunk eine Netzwerkkarte, die getaggte Frames unverändert durchreicht.

## 3.5 Debian 13 installieren

Mit dem offiziellen **Debian-13-netinst**-Image (amd64):

1. **Sprache/Tastatur** nach Wunsch. Zeitzone ist frei wählbar, da die Appliance intern UTC verwendet.
2. **Netzwerk:** feste IP-Adresse konfigurieren (Netzwerkkarte 1), Hostname `siem`, Domäne `firma.local`. Netzwerkkarte 2 (Trunk) **nicht** konfigurieren.
3. **Benutzer:** Root-Kennwort leer lassen (dann erhält der erste Benutzer sudo-Rechte) oder setzen. Einen Benutzer für die Installation anlegen (z. B. `install`).
4. **Partitionierung:** nur **Disk 1** verwenden („Geführt – vollständige Festplatte“ auf Disk 1). **Disk 2 unberührt lassen**, darum kümmert sich `install.sh`.
5. **Softwareauswahl:** **nur** „SSH server“ und „Standard-Systemwerkzeuge“. **Keine** Desktop-Umgebung, kein Webserver.
6. Installation abschließen, neu starten, per SSH anmelden.

> **Hinweis:** Weitere Pakete müssen nicht vorab installiert werden. Alles Nötige installiert `install.sh`. Auf der VM sollen keine anderen Dienste laufen.

## 3.6 Installationspaket beziehen

Es gibt zwei Wege. Beide führen zum selben Ergebnis.

### Variante A – direkt von GitHub (empfohlen)

Auf der VM:

```bash
curl -fsSLO https://github.com/giti4ge/kmu-siem-releases/releases/latest/download/bootstrap.sh
less bootstrap.sh                     # kurz ansehen – es lädt nur und prüft die Signatur
sudo bash bootstrap.sh                # neueste Stable-Version
sudo bash bootstrap.sh --version v1.0.0 --preflight   # bestimmte Version, nur prüfen
```

`bootstrap.sh`:
1. lädt das Installationspaket der gewünschten Version samt Signatur von GitHub,
2. prüft die Signatur mit dem eingebetteten öffentlichen Schlüssel des Dienstleisters,
3. entpackt das Paket nach `~/siem-installer-<version>`,
4. startet `install.sh` mit den übergebenen Optionen.

**Privates Distributions-Repository:** Solange die Releases nicht öffentlich sind, wird ein **Zugangstoken** benötigt. Der Dienstleister stellt dafür je Kunde ein read-only Token aus.

```bash
# Token einmalig in eine Datei legen (nicht in die Shell-History tippen):
install -m 600 /dev/null ~/github.token && nano ~/github.token
curl -fsSL -H "Authorization: Bearer $(cat ~/github.token)" \
  -H "Accept: application/octet-stream" -o bootstrap.sh \
  "$(curl -fsSL -H "Authorization: Bearer $(cat ~/github.token)" \
     https://api.github.com/repos/giti4ge/kmu-siem-releases/releases/latest \
     | jq -r '.assets[] | select(.name=="bootstrap.sh") | .url')"
sudo bash bootstrap.sh --token-file ~/github.token
```

> **⚠ Zu verifizieren:** Der genaue Download-Weg für private Releases wird bei der Implementierung festgelegt. Ziel ist ein einzeiliger Aufruf.

Das Token wird bei der Installation verschlüsselt auf der Appliance gespeichert und für spätere Updates verwendet. Die Token-Datei wird danach gelöscht.

### Variante B – Paket manuell übertragen

Für Umgebungen, in denen GitHub nur vom Arbeitsplatz aus erreichbar ist:

```bash
# Auf dem Arbeitsplatz:
scp siem-installer-1.0.0.tar.gz SHA256SUMS SHA256SUMS.sig install@siem.firma.local:~

# Auf der VM:
sha256sum -c SHA256SUMS --ignore-missing
tar xzf siem-installer-1.0.0.tar.gz
cd siem-installer-1.0.0
```

Den Prüfwert in `SHA256SUMS` mit dem veröffentlichten Wert (Release-Seite) vergleichen. Das Skript prüft zusätzlich vor jeder Änderung die Ed25519-Signatur seines Manifests.

Das Installationspaket steht auf der GitHub-Release-Seite der jeweiligen Version zum Download bereit.

## 3.7 Voraussetzungen prüfen (Preflight)

```bash
sudo ./install.sh --preflight
```

Der Preflight ändert **nichts** am System. Er prüft:

| Prüfung | Bei Fehler |
|---|---|
| Debian 13, amd64 | Abbruch |
| CPU, RAM, freier Speicher, zweite Disk vorhanden und leer | Abbruch bzw. Warnung (ohne Disk 2) |
| Feste IP, DNS-Auflösung des eigenen FQDN | Warnung |
| Zeit synchron | Warnung |
| Internet-Ziele (3.2) direkt oder über Proxy erreichbar | Abbruch |
| Keine belegten Ports (22 ausgenommen), kein fremdes Docker, keine Desktop-Umgebung | Abbruch |

Das Ergebnis wird als Tabelle (✔ / ⚠ / ✘) ausgegeben und nach `/var/log/siem-install.log` geschrieben.

## 3.8 Installation

### Interaktiv

```bash
sudo ./install.sh
```

Das Skript fragt der Reihe nach:

1. **Sprache** (Deutsch/Englisch)
2. **FQDN** der Appliance (Vorschlag aus dem System)
3. **NTP-Server** (Vorschlag: DNS-Server bzw. DCs)
4. **Proxy** (optional, mit Benutzer/Kennwort)
5. **Daten-Disk** (Auswahl der erkannten leeren Disk; **wird vollständig gelöscht** – Bestätigung durch Eingabe des Gerätenamens)
6. **SSH-Public-Key** für den Admin-Benutzer `siemadmin` (einfügen oder Datei angeben)
7. **Kennwort** für `siemadmin` (sudo)
8. **Erstes Web-UI-Konto** `admin` (Kennwort)
9. **VLAN-Trunk** (optional: Netzwerkkarte und VLAN-IDs, auch später im Web-UI möglich)
10. **Zusammenfassung** → Bestätigen

Danach läuft die Installation ohne weitere Eingaben. Fortschritt wird schrittweise angezeigt:

| Schritt | Inhalt |
|---|---|
| 1 Basis | APT-Quellen, Systemaktualisierung, Abhängigkeiten |
| 2 Daten-Disk | LVM (`siem/data`), Dateisystem, Einhängen unter `/opt/siem/data` |
| 3 Härtung | Kernel-Parameter, Module, SSH, auditd, AIDE, AppArmor, chrony, automatische Sicherheitsupdates, Benutzer `siemadmin` |
| 4 Docker | Docker Engine aus dem offiziellen Repository, gehärtete Daemon-Konfiguration |
| 5 Firewall | nftables mit Standardregeln |
| 6 Host-Dienste | `siem-hostd`, systemd-Units und Timer |
| 7 Anwendung | Container-Images laden und prüfen, Zertifikate, Schlüssel, Start, Initialisierung von OpenSearch, Web-UI-Konto |
| 8 Selbsttest | Dienste, Test-Ereignis, Firewall, Härtungsprüfung |

Am Ende zeigt das Skript:

```
✔ Installation abgeschlossen (Version 1.0.0)
  Web-UI:        https://siem.firma.local
  Zertifikat:    SHA256 Fingerprint AB:CD:…
  SSH:           siemadmin@siem.firma.local (nur Schlüssel)
  Log:           /var/log/siem-install.log
  Nächster Schritt: Web-UI öffnen und Einrichtungsassistent durchlaufen.
```

### Unbeaufsichtigt (Antwortdatei)

Für wiederholbare Installationen (z. B. mehrere Kunden):

```bash
cp antworten.env.example antworten.env
nano antworten.env
sudo ./install.sh --unattended antworten.env
```

Auszug `antworten.env`:

```bash
SIEM_LANG=de
SIEM_FQDN=siem.firma.local
SIEM_NTP=dc01.firma.local,dc02.firma.local
SIEM_PROXY=                         # z. B. http://proxy.firma.local:3128
SIEM_DATA_DISK=/dev/sdb
SIEM_DATA_DISK_CONFIRM=yes          # Disk wird gelöscht
SIEM_ADMIN_SSH_KEY_FILE=/home/install/siemadmin.pub
SIEM_ADMIN_PASSWORD_FILE=/root/.siem-admin-pw    # Datei statt Klartext
SIEM_WEB_ADMIN_PASSWORD_FILE=/root/.siem-web-pw
SIEM_TRUNK_IF=                      # z. B. ens224
SIEM_TRUNK_VLANS=                   # z. B. 10,20,30
```

> **Hinweis:** Kennwort-Dateien werden nach erfolgreicher Installation sicher gelöscht. Klartextwerte in der Antwortdatei werden gemeldet.

### Schutz vor Aussperren

- Die Kennwort-Anmeldung per SSH wird **nur** abgeschaltet, wenn ein SSH-Key hinterlegt wurde **und** eine Testanmeldung damit bestätigt ist. Andernfalls bleibt sie aktiv und das Dashboard warnt.
  - **Interaktiv:** Nach der Härtung fordert das Skript auf, in einer **neuen** SSH-Sitzung `ssh siemadmin@<appliance>` mit dem Schlüssel zu testen, und fragt nach dem Ergebnis. Die laufende Sitzung dabei nicht schließen.
  - **Antwortdatei:** `SIEM_SSH_PASSWORD_AUTH=no` schaltet die Kennwort-Anmeldung ab. Das setzt voraus, dass der hinterlegte Schlüssel vorher geprüft wurde.
- Die laufende SSH-Sitzung bleibt während der Installation bestehen, die eigene Quell-IP wird in der Firewall zugelassen.
- Der bei der Debian-Installation angelegte Benutzer (z. B. `install`) verliert nach der Installation den SSH-Zugang. Die Anmeldung erfolgt künftig als `siemadmin`.

## 3.9 Abbruch, Fortsetzen, Reparatur

| Situation | Befehl |
|---|---|
| Installation wurde unterbrochen (Netzwerk, Stromausfall, Fehler) | `sudo ./install.sh --resume` – setzt am letzten erfolgreichen Schritt fort |
| System weicht vom Sollzustand ab (z. B. manuelle Änderungen, Härtung überprüfen) | `sudo /opt/siem/host/install.sh --repair` – stellt Pakete, Härtung und Dienste wieder her, **ohne** Daten zu verändern |
| Nur prüfen | `sudo /opt/siem/host/install.sh --preflight` |

Jeder Schritt ist wiederholbar. Ein zweiter Lauf auf einem korrekten System ändert nichts.

## 3.10 Erste Anmeldung und Einrichtungsassistent

1. `https://siem.firma.local` aufrufen und den Zertifikats-Fingerabdruck mit der Ausgabe des Skripts vergleichen.
2. Mit `admin` anmelden und **TOTP-MFA einrichten** (Pflicht für Administratoren).
3. Der **Einrichtungsassistent** führt durch:
   - E-Mail und Teams (Testnachricht),
   - Firewall-Allowlists,
   - Zertifikat (Root-CA verteilen oder eigenes Zertifikat hochladen),
   - Update-Modus und Wartungsfenster,
   - erste Quellen.
4. Details in [Kapitel 4 – Erstkonfiguration](04-erstkonfiguration.md).

## 3.11 Abnahme-Checkliste nach Installation

- [ ] Selbsttest von `install.sh` ohne Fehler, Log gesichert
- [ ] SSH als `siemadmin` mit Schlüssel möglich, Kennwort-Anmeldung deaktiviert
- [ ] Web-UI erreichbar, MFA für `admin` aktiv
- [ ] **Dashboard → Systemstatus**: alle Dienste grün
- [ ] Zeit synchron (Abweichung < 1 s)
- [ ] Testmail und Teams-Testnachricht empfangen
- [ ] GitHub erreichbar, Zugangstoken gültig (**System → Updates → Verbindung testen**)
- [ ] Firewall-Allowlists auf die tatsächlichen Quellen eingeschränkt
- [ ] Erstes Backup erstellt und extern abgelegt
- [ ] Antwortdatei/Kennwort-Dateien gelöscht
