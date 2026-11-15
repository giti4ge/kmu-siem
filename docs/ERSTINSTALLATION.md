# Erstinstallation und Fehlerrückmeldung

Stand: 2026-11-15 · Version 0.1.0-rc.1 · Begleitdokument: [TESTCHECKLISTE.md](TESTCHECKLISTE.md)

Diese Anleitung führt von der leeren VM bis zur ersten Fehlermeldung. Das ausführliche Soll-Handbuch steht unter [handbuch/03-installation.md](handbuch/03-installation.md); wo dieses Dokument davon abweicht, gilt dieses (Testpaket statt `bootstrap.sh`, da das Release-Repository noch nicht existiert).

## 1. Voraussetzungen

| Was | Wert |
|---|---|
| VM | Debian 13 minimal + SSH-Server, amd64 |
| Ressourcen | Test: 4 vCPU, 16 GB RAM (statisch), Disk 1 40 GB; Disk 2 (Daten) leer, mindestens 100 GB (Produktion 500 GB) |
| Netz | feste IP, DNS-Name (A-Record) für den FQDN, Internet (HTTPS) direkt oder per Proxy |
| Zugang | SSH-Schlüsselpaar für `siemadmin` (Erstellung: Abschnitt 2) |
| Arbeitsplatz | `gh` (GitHub CLI) angemeldet oder Browser mit Zugriff auf `giti4ge/kmu-siem` |

Debian-Installation: nur „SSH server“ und „Standard-Systemwerkzeuge“, Disk 2 unberührt lassen (Details: Handbuch 3.5).

## 2. SSH-Schlüsselpaar erstellen

Der Installer fragt nach dem **öffentlichen** Schlüssel (Public Key) für den Benutzer `siemadmin`. Der private Schlüssel bleibt auf dem Arbeitsplatz.

```powershell
# Arbeitsplatz (Windows PowerShell)
ssh-keygen -t ed25519 -C "siemadmin"
type $env:USERPROFILE\.ssh\id_ed25519.pub     # eine Zeile: ssh-ed25519 AAAA... siemadmin
```

- Speicherort bestätigen (Standard `C:\Users\<name>\.ssh\id_ed25519`), Passphrase empfohlen.
- `id_ed25519` = privat, nie weitergeben. `id_ed25519.pub` = öffentlich, kommt in den Installer.
- Bei der Frage „SSH-Public-Key“ entweder die komplette Zeile **einfügen** (einfachste Variante) oder den Pfad einer Datei **auf der VM** angeben, z. B. nach `scp $env:USERPROFILE\.ssh\id_ed25519.pub install@<vm>:~/siemadmin.pub` den Pfad `/home/install/siemadmin.pub`.
- Nach der Härtung in einer **neuen** Sitzung testen: `ssh siemadmin@<vm>` (bei anderem Schlüsselnamen `ssh -i <privater-schlüssel> siemadmin@<vm>`). Erst nach erfolgreicher Anmeldung im Installer bestätigen; dann wird die Kennwort-Anmeldung abgeschaltet.

## 3. Testpaket beziehen

Das Paket entsteht in der CI (Actions → *Testpaket (Installer-Tarball)* → Run workflow, Branch/Tag `main` bzw. `v0.1.0-rc.1`). Das Ergebnis ist ein Artefakt `kmu-siem-testpaket-<version>-<commit>` mit `.tar.gz` und `.sha256` (14 Tage gültig). Der Entwurf des Releases `v0.1.0-rc.1` enthält dasselbe Paket als Anhang.

```bash
# Arbeitsplatz (Git Bash / PowerShell mit gh)
gh run download <run-id> -R giti4ge/kmu-siem -D testpaket
cd testpaket/kmu-siem-testpaket-*
sha256sum -c *.sha256                    # muss "OK" melden
scp kmu-siem-testpaket-*.tar.gz install@<vm>:~
```

## 4. Installation

```bash
ssh install@<vm>
sudo -i
tar -xzf /home/install/kmu-siem-testpaket-*.tar.gz && cd kmu-siem-testpaket-*
bash host/install.sh --preflight          # ändert nichts; alle ✘ beheben
bash host/install.sh                      # interaktiv, siehe Handbuch 3.8
```

Wichtig:

- Die Daten-Disk wird **vollständig gelöscht** (Bestätigung durch Eingabe des Gerätenamens).
- Nach der Härtung in einer **neuen** SSH-Sitzung `ssh siemadmin@<vm>` mit Schlüssel testen und erst dann bestätigen; die alte Sitzung offen lassen.
- Der Benutzer `install` verliert danach den SSH-Zugang.
- Abbruch: `bash host/install.sh --resume`. Reparatur: `bash /opt/siem/host/install.sh --repair`.
- Installationsprotokoll: `/var/log/siem-install.log`.

Danach: `https://<fqdn>` öffnen, Fingerabdruck mit der Ausgabe des Skripts vergleichen, als `admin` anmelden, MFA einrichten, Einrichtungsassistent durchlaufen. Weiter mit der [Testcheckliste](TESTCHECKLISTE.md).

## 5. Kennwort oder MFA vergessen / Gerät verloren

**Normalfall (ein anderer Administrator ist vorhanden):** Web-UI → *Benutzer* → Benutzer öffnen → *Kennwort zurücksetzen* (neues Kennwort vergeben; der Benutzer muss es beim nächsten Login ändern) bzw. *MFA zurücksetzen*. Der eigene Account kann so nicht zurückgesetzt werden. Der Benutzer richtet TOTP beim nächsten Login mit der Authenticator-App neu ein. Beides beendet alle Sitzungen des Benutzers und wird im Audit-Log protokolliert.

**Notfall (einziger Administrator ist ausgesperrt):** per SSH als `siemadmin` auf der Appliance, mit Kennwort von der Standardeingabe (landet nicht in der Shell-History):

```bash
# MFA zurücksetzen – beim nächsten Login wird TOTP neu eingerichtet
sudo docker exec siem-api python -m siem_api.cli reset-mfa --username admin

# Kennwort setzen (mind. 12 Zeichen, Richtlinie wird geprüft; Änderung beim nächsten Login erzwungen)
read -rs PW && echo "$PW" | sudo docker exec -i siem-api python -m siem_api.cli reset-password --username admin --password-stdin; unset PW
```

Beide Befehle heben auch eine Kontosperre auf (Kennwort) bzw. beenden Sitzungen und erzeugen einen Audit-Eintrag (`actor: cli`). Ist auch der SSH-Zugang verloren, hilft nur Konsolenzugriff auf die VM.

## 6. Fehler rückmelden

Ablauf je Auffälligkeit (ausführlich: [BETRIEB.md](BETRIEB.md)):

1. **Issue anlegen** unter https://github.com/giti4ge/kmu-siem/issues/new/choose mit der Vorlage *Fehler*, *Parser-Format* oder *Wunsch*. Die Checklisten-Nummer (z. B. `T-4.2`) in den Titel schreiben.
2. **Diagnosepaket anhängen** (Web-UI → *Wartung* → Diagnosepaket). Es enthält Versionen, Status und Fehlerzeilen ohne Geheimnisse und ohne Ereignisinhalte; Namen und Adressen sind pseudonymisiert.
3. **Bei Parserproblemen:** *Nicht erkannte Quellen* → „Probe exportieren“ (pseudonymisiert) und an das Issue hängen. Keine unpseudonymisierten Logs ins Issue stellen.
4. **Bei Installationsfehlern:** letzte 100 Zeilen von `/var/log/siem-install.log` und den Schritt (`base`, `data`, `hardening`, …) angeben; Geheimnisse vorher entfernen.
5. **Bei Web-UI-Fehlern:** Seite, Uhrzeit (UTC), Meldungstext, ggf. Screenshot; Einträge in *System-Protokoll* und *Audit-Log* im Zeitraum.
6. Wenn nötig: **Support-Zugang** (Web-UI → Support-Zugang) für begrenzte Zeit freigeben. Der Zugang ist schlüsselgebunden, auf Diagnosebefehle beschränkt und ohne Zugriff auf Ereignisdaten.

Schweregrade für die Issues:

| Stufe | Bedeutung |
|---|---|
| Blocker | Installation bricht ab, Anmeldung oder Ereignisempfang unmöglich, Datenverlust, Aussperrung |
| Hoch | Funktion liefert falsche Ergebnisse (Parser, Alarm, Archivprüfung) |
| Mittel | Funktion eingeschränkt, Umgehung möglich |
| Niedrig | Darstellung, Text, Komfort |

## 7. Bekannte Einschränkungen (nicht als Fehler melden)

Siehe [STATUS.md](STATUS.md) und die Release-Notes: Windows-Skript nicht an echter Domäne geprüft, PDF über Browser-Druck, Update-Einspielen per `install.sh --upgrade`, kein Content-Kanal, SFTP/SMB-Direktanbindung fehlt, Parserformate teils aus Dokumentation abgeleitet. **Abweichungen davon sind ausdrücklich erwünscht** – genau dafür ist der Test.
