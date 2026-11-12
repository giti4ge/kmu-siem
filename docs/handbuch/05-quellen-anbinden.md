# 5. Quellen anbinden

> Gilt ab Version: 1.0.0 · Stand: Soll-Dokumentation (Spezifikation 2.3.0)

Alle Quellen werden unter **Quellen & Onboarding** angelegt. Jede Quelle hat einen Assistenten, der die nötigen Einstellungen auf dem Gerät anzeigt und anschließend prüft, ob Ereignisse ankommen.

> **Wichtig:** Die Gerätebefehle in diesem Kapitel sind Beispiele. Sie sind mit **⚠ Zu verifizieren** markiert und werden im Testlabor gegen die jeweilige Firmware bestätigt. Maßgeblich ist die Anzeige im Assistenten der installierten Version.

## 5.1 Allgemeines Vorgehen

1. Quelle anlegen: Typ, Name, IP-Adresse(n), Kritikalität, Asset-Gruppe.
2. Gerät nach Anleitung des Assistenten konfigurieren.
3. **Verbindung prüfen**: Der Assistent zeigt die ersten Ereignisse und den Parser-Status (erkannt / teilweise / unparsed).
4. Heartbeat-Schwelle festlegen (Standard 15 Minuten für Firewall und DCs, 60 Minuten für Switches).
5. Firewall-Allowlist der Appliance um die Quelle ergänzen (der Assistent schlägt das vor).

Status je Quelle: 🟢 Ereignisse aktuell · 🟡 verzögert · 🔴 Heartbeat überschritten · ⚪ deaktiviert.

## 5.2 Fortinet FortiGate

### 5.2.1 Syslog über TLS

1. Root-CA der Appliance auf der FortiGate importieren (**System → Certificates → Import → CA Certificate**).
2. Syslog konfigurieren (CLI) – **⚠ Zu verifizieren** je FortiOS-Version:

   ```
   config log syslogd setting
       set status enable
       set server "10.0.10.50"
       set mode reliable
       set port 6514
       set enc-algorithm high
       set format default
   end
   config log syslogd filter
       set severity information
       set forward-traffic enable
       set local-traffic disable
       set multicast-traffic disable
       set sniffer-traffic disable
   end
   ```

3. In den Firewall-Policies festlegen, welche Policies Traffic loggen (**Log Allowed Traffic: Security Events** oder **All Sessions**).

> **Achtung – Datenmenge:** „All Sessions“ auf internen Policies kann ein Vielfaches der übrigen Logs erzeugen. Empfehlung: „All Sessions“ für Inter-VLAN- und Internet-Policies, „Security Events“ für den Rest. Die Appliance zeigt die Datenmenge je Quelle unter **Quellen** an.

### 5.2.2 REST-API (Asset-Korrelation und IP-Sperre)

1. Admin-Profil `siem-api` anlegen: Lesen für *Network*, *Log & Report*, *System*; Schreiben nur für *Firewall → Address* (nur nötig für Active Response).
2. REST-API-Admin `siem` mit diesem Profil anlegen, **Trusted Hosts** = IP der Appliance, Token erzeugen.
3. Für Active Response: Adressgruppe `SIEM_BLOCK` anlegen und in eine Deny-Policy (oben in der Liste, Quelle `SIEM_BLOCK` → alle; und umgekehrt) einbinden.
4. Token und Gruppennamen im Assistenten eintragen und **Verbindung prüfen**.

## 5.3 Switches

### 5.3.1 Geräteprofile

| Profil | Syslog | SNMPv3 | Traps | Port-Matrix |
|---|---|---|---|---|
| ArubaOS-Switch | ✔ | ✔ | ✔ | vollständig |
| FS S3900 | ✔ | ✔ | ✔ | vollständig |
| Aruba Instant On | eingeschränkt | modell-/modusabhängig | – | reduziert |

### 5.3.2 Zugangsdaten SNMPv3

Im Assistenten werden Benutzername, Authentifizierung (SHA-256 bevorzugt, sonst SHA) und Verschlüsselung (AES) festgelegt. Diese Werte werden auf dem Switch identisch eingetragen. Pro Kunde sollte ein eigener SNMP-Benutzer mit langen Kennwörtern verwendet werden.

### 5.3.3 ArubaOS-Switch (⚠ Zu verifizieren)

```
logging 10.0.10.50
logging severity info
snmpv3 enable
snmpv3 only
snmpv3 user siem auth sha <AUTH-KENNWORT> priv aes <PRIV-KENNWORT>
snmpv3 group operatorauth user siem sec-model ver3
snmp-server host 10.0.10.50 community "siem" trap-level all
lldp run
```

### 5.3.4 FS S3900 (⚠ Zu verifizieren)

```
logging 10.0.10.50
logging trap informational
snmp-server enable
snmp-server view siemview 1.3.6.1 include
snmp-server group siemgroup v3 priv read siemview
snmp-server user siem siemgroup v3 auth sha <AUTH-KENNWORT> priv aes <PRIV-KENNWORT>
snmp-server host 10.0.10.50 version 3 priv siem
lldp enable
```

### 5.3.5 Aruba Instant On (⚠ Zu verifizieren)

Der Funktionsumfang hängt vom Modell und der Verwaltungsart (Cloud-App oder lokale Web-Verwaltung) ab. Der Assistent prüft beim Anlegen, welche Daten verfügbar sind, und zeigt in der Port-Matrix nur diese an. Verfügbare Syslog-Ereignisse werden trotzdem ausgewertet.

### 5.3.6 Was abgefragt wird

| Daten | MIB | Intervall |
|---|---|---|
| Port-Status, Geschwindigkeit, Beschreibung | IF-MIB | 60 s |
| VLAN-Zuordnung je Port | Q-BRIDGE-MIB | 5 min |
| MAC-Adressen je Port und VLAN | Q-BRIDGE-/BRIDGE-MIB | 5 min |
| Nachbarn (Uplinks, Trunks) | LLDP-MIB | 5 min |

## 5.4 Windows-Server und -Clients (WEF)

Die Anbindung erfolgt **ohne Agenten** über die in Windows eingebaute Ereignisweiterleitung. Die Server senden ihre Ereignisse selbst an die Appliance. Die Anmeldung erfolgt per Kerberos.

### 5.4.1 Voraussetzungen

- DNS-A-Record für `siem.firma.local`
- Zeit der Appliance synchron zur Domäne
- Firewall: Server → Appliance 5985/tcp
- Ein Domain-Admin für die einmalige Einrichtung

### 5.4.2 Einrichtung mit dem Assistenten

**Quellen & Onboarding → Windows-Domäne hinzufügen**

1. Domäne (`firma.local`), FQDN der Appliance und die OUs der Server bzw. Clients eintragen und je OU eine Rolle zuordnen (*Domain Controller*, *Exchange*, *Member-Server*, *Client*).
2. Überwachte Pfade für das File-Integrity-Monitoring festlegen (optional, siehe 5.4.5).
3. **PowerShell-Skript herunterladen** und auf einem DC als Domain-Admin ausführen. Das Skript:
   - legt das Dienstkonto `svc-siem-wec` an und registriert den Dienstnamen `HTTP/siem.firma.local`,
   - exportiert die Keytab-Datei `siem.keytab`,
   - legt die GPO **„SIEM Event Forwarding“** an und verknüpft sie mit den gewählten OUs. Die GPO enthält:
     - WinRM-Dienst automatisch starten,
     - Ziel-Subscription-Manager `Server=http://siem.firma.local:5985/wsman/SubscriptionManager/WEC,Refresh=60`,
     - `NETWORK SERVICE` in die Gruppe *Event Log Readers* (Zugriff auf das Security-Log),
     - die empfohlene **Advanced Audit Policy**,
     - die SACLs für das File-Integrity-Monitoring,
   - prüft die Audit-Einstellungen der Server und schreibt einen Bericht.
4. **Keytab hochladen** und optional den Prüfbericht.
5. Warten, bis die GPO auf den Servern greift (oder `gpupdate /force`). Die Server erscheinen anschließend unter **Quellen** mit Status und Ereignisrate.

> **Achtung:** Die Keytab enthält das Geheimnis des Dienstkontos. Nach dem Hochladen auf dem DC löschen. Das Kennwort des Dienstkontos läuft nicht ab. Bei einer Änderung muss eine neue Keytab erzeugt werden.

### 5.4.3 Manuelle Einrichtung (ohne Skript)

Für Umgebungen, in denen kein Skript ausgeführt werden darf:

```powershell
# Dienstkonto und SPN
New-ADUser -Name "svc-siem-wec" -AccountPassword (Read-Host -AsSecureString) `
  -Enabled $true -PasswordNeverExpires $true -KerberosEncryptionType AES256
setspn -S HTTP/siem.firma.local svc-siem-wec

# Keytab exportieren
ktpass /princ HTTP/siem.firma.local@FIRMA.LOCAL /mapuser FIRMA\svc-siem-wec `
  /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /pass * /out siem.keytab
```

Die GPO-Einstellungen sind im Assistenten unter **Manuelle Anleitung** einzeln aufgeführt.

### 5.4.4 Was gesammelt wird

| Rolle | Ereignisse (Auszug) |
|---|---|
| Domain Controller | Anmeldungen (4624/4625/4648/4768/4769/4771/4776), Konten- und Gruppenänderungen (4720–4767), AD-Änderungen (5136/5137/5139/5141), DNS-Server, Directory Service, System |
| Exchange | MSExchange Management (Admin-Audit), Application, Security, System |
| Member-Server | Anmeldungen, Prozessstart mit Kommandozeile (4688), Dienstinstallation (7045), geplante Tasks (4698–4702), PowerShell (4104), Defender, System |
| Clients (optional) | Anmeldefehler, lokale Admin-Änderungen, Defender, Dienstinstallation, USB-Geräte (6416) |

Die vollständige Liste steht im [Anhang B](anhang.md#b-windows-ereignis-ids). Clients erzeugen in Summe viel Datenmenge. Der Assistent zeigt vor dem Aktivieren eine Prognose.

### 5.4.5 File-Integrity-Monitoring

Für jeden Server werden Pfade festgelegt (z. B. `D:\Freigaben\Finanzen`, `C:\Windows\System32\drivers\etc`). Die GPO setzt dafür Überwachungseinträge (SACL) für *Schreiben, Löschen, Berechtigungen ändern*. Lesezugriffe werden **nicht** überwacht.

> **Hinweis:** Erfasst wird, **wer** mit **welchem Programm** eine Datei geändert, gelöscht oder deren Rechte geändert hat. Ob sich der Dateiinhalt geändert hat (Hash), ist ohne Agent nicht feststellbar.

### 5.4.6 Audit-Policy-Check

Unter **Change-Audit & FIM → Hardening-Report** zeigt die Appliance je Server, ob die Audit-Einstellungen der Empfehlung entsprechen. Fehlende Einstellungen führen dazu, dass Erkennungsregeln nicht greifen können. Sie werden mit der betroffenen Regel angezeigt.

### 5.4.7 Nicht-Domänen-Server (optional)

Über Port 5986 (HTTPS) mit Client-Zertifikat. Der Assistent erstellt das Zertifikat und die nötigen Befehle.

## 5.5 Linux-Server

Die Anbindung erfolgt über das vorhandene **rsyslog** mit TLS.

1. **Quellen & Onboarding → Linux-Server**: Distribution wählen, Root-CA und Konfiguration herunterladen.
2. Auf dem Server (Beispiel Debian/Ubuntu):

   ```bash
   apt install rsyslog-gnutls
   cp siem-ca.pem /etc/ssl/siem-ca.pem
   ```

   `/etc/rsyslog.d/90-siem.conf`:

   ```
   global(DefaultNetstreamDriverCAFile="/etc/ssl/siem-ca.pem")
   action(type="omfwd" target="siem.firma.local" port="6514" protocol="tcp"
          StreamDriver="gtls" StreamDriverMode="1"
          StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="siem.firma.local"
          queue.type="LinkedList" queue.filename="siem_fwd" queue.maxDiskSpace="1g"
          queue.saveOnShutdown="on" action.resumeRetryCount="-1")
   ```

   ```bash
   systemctl restart rsyslog
   ```

3. Optional die mitgelieferten **auditd-Regeln** einspielen (Benutzer-, sudo- und Konfigurationsänderungen).

RHEL-Familie: Paket `rsyslog-gnutls` über `dnf`. SUSE: über `zypper`. Die Konfiguration ist identisch.

## 5.6 Sophos Central

1. In Sophos Central: **Globale Einstellungen → API-Anmeldedaten verwalten → Anmeldedaten hinzufügen**. Die Rolle muss Lesezugriff und für XDR-Abfragen die entsprechende Berechtigung haben (**⚠ Zu verifizieren:** genaue Rollenbezeichnung für XDR-Data-Lake-Abfragen).
2. Client-ID und Client-Secret im Assistenten eintragen.
3. Die Appliance erkennt Region und Tenant und prüft, ob XDR-Data-Lake-Abfragen möglich sind:
   - **XDR verfügbar:** Modus *Data Lake* (Detections, verdächtige Prozesse, Anmeldungen, Isolationsstatus; Abfrage alle 10 Minuten).
   - **Nicht verfügbar:** automatisch Modus *SIEM-API* (Events und Alerts).
4. Der aktive Modus wird angezeigt und kann manuell umgestellt werden.

## 5.7 Ikarus

In der IKARUS-Verwaltung (security.manager, mail.security, web.security) die Syslog-Weiterleitung auf `siem.firma.local:514` (TCP bevorzugt) einrichten. **⚠ Zu verifizieren:** Menüpfade und verfügbare Formate je Produkt.

## 5.8 Andere Syslog-Quellen

Jede Syslog-Quelle (RFC 3164/5424, CEF, JSON) kann als **Generische Quelle** angebunden werden. Ereignisse ohne passenden Parser erscheinen unter **Quellen → Unparsed** (siehe 11.4). Daraus können Parser nachgezogen werden.
