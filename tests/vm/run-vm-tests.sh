#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2016  # Befehle in einfachen Anführungszeichen laufen bewusst erst in der VM; pass() schlägt nie fehl
# VM-Test: install.sh auf einer frischen Debian-13-VM (QEMU, Debian-Cloud-Image).
#
# Entspricht der Ausgangssituation der Spezifikation: frisches Debian 13 mit SSH,
# zweite leere Disk. Läuft auf einem Linux-Host mit qemu (CI: GitHub Actions).
#
# Tests:
#   1. Preflight mit realen Grenzwerten: VM ist bewusst zu klein → RAM/CPU-Fehler,
#      OS/systemd/Daten-Disk/Internet OK
#   2. Preflight mit abgesenkten Grenzwerten → keine Fehler
#   3. Preflight mit nicht erreichbarem Proxy → Internet-Fehler
#   4. Preflight verändert nichts (Pakete, /etc, /usr, /opt, /var/lib/siem)
#   5. Unbeaufsichtigte Installation der Host-Schritte (base … firewall):
#      Pakete, LVM-Daten-Disk, Härtung, SSH (nur siemadmin mit Schlüssel),
#      auditd, chrony, Docker, nftables inkl. Wirksamkeit der Freigaben
#   6. Idempotenz: erneuter Lauf aller Host-Schritte ändert nichts
#   7. Preflight nach Teilinstallation meldet keine Fehler durch eigene Änderungen
#   8. siem-hostd: Socket-Rechte, Aktions-Allowlist, Validierung, Dead-Man's-Switch
#      (Rücknahme, Bestätigung, Aussperren per SSH, Neustart während der Frist)
#   9. Anwendung: Syslog UDP/TCP/TLS von extern Ende-zu-Ende, ECS-Felder, Firewall für
#      Syslog, OpenSearch-Sicherheit/Templates/ISM, Proxy (TLS 1.3, Header, WAF),
#      Disk-Puffer über Vector-Neustart bei ausgefallenem OpenSearch
#  10. Integrität (AIDE, rkhunter), Lynis-Index ≥ 80, ergänzende Härtung; --repair stellt
#      manipulierte Konfiguration und gestoppte Container wieder her, ohne Daten zu verlieren
#
# Umgebungsvariablen: VM_RAM_MB (4096), VM_CPUS (2), WORKDIR (./.vm), DEBIAN_IMAGE_URL
set -euo pipefail

# shellcheck source=tests/vm/lib.sh
. "$(dirname "$0")/lib.sh"
VM_HOSTFWD="hostfwd=tcp:127.0.0.1:8443-:443,hostfwd=tcp:127.0.0.1:8081-:8081,hostfwd=tcp:127.0.0.1:9443-:8443,hostfwd=tcp:127.0.0.1:5514-:514,hostfwd=udp:127.0.0.1:5514-:514,hostfwd=tcp:127.0.0.1:6514-:6514"
vm_boot

run_pf() {  # run_pf [ENV…] -- [ARGS…]; Ausgabe in $OUT, Exit in $RC
    local envs=() ; while [[ $# -gt 0 && $1 != -- ]]; do envs+=("$1"); shift; done; shift || true
    set +e
    OUT=$(vm "sudo env NO_COLOR=1 ${envs[*]} bash ~/siem/host/install.sh --preflight $*" 2>&1)
    RC=$?
    set -e
    printf '%s\n' "$OUT"
}

# --- Test 1 ------------------------------------------------------------------
log "Test 1: Preflight mit realen Grenzwerten"
vm 'sudo touch /root/.pf-marker; sleep 1'
PKGS_BEFORE=$(vm "dpkg-query -W -f='\${Package} \${Version}\n' | sha256sum")
run_pf --
[[ $RC -eq 2 ]] && pass "Exit-Code 2" || fail "Exit-Code 2 erwartet, erhalten $RC"
expect '✔ Betriebssystem +Debian 13' "Debian 13 erkannt"
expect '✔ systemd' "systemd erkannt"
expect '✘ Arbeitsspeicher' "zu wenig RAM erkannt"
expect '✘ CPU' "zu wenige CPUs erkannt"
expect '✔ Daten-Disk +/dev/vdb' "leere Daten-Disk /dev/vdb erkannt"
expect '✔ Internet: Debian ' "Internet erreichbar"
expect '✔ Internet: GitHub Container Registry' "ghcr.io erreichbar"
expect '⚠ IP-Adresse .*DHCP' "DHCP-Adresse als Warnung"
expect 'nur lokal auf 127\.0\.1\.1' "FQDN nur in /etc/hosts erkannt"

# --- Test 2 ------------------------------------------------------------------
log "Test 2: Preflight mit abgesenkten Grenzwerten"
run_pf "${LOW[@]}" --
[[ $RC -le 1 ]] && pass "keine Fehler (Exit $RC)" || fail "Exit 0/1 erwartet, erhalten $RC"
expect 'Prüfgrenzen wurden per Umgebungsvariable geändert' "Hinweis auf geänderte Grenzwerte"

# --- Test 3 ------------------------------------------------------------------
log "Test 3: nicht erreichbarer Proxy"
run_pf "${LOW[@]}" SIEM_NET_TIMEOUT=3 -- --proxy http://127.0.0.1:9
[[ $RC -eq 2 ]] && pass "Exit-Code 2" || fail "Exit-Code 2 erwartet, erhalten $RC"
expect '✘ Internet: Debian .*über Proxy' "Proxy-Fehler erkannt"

# --- Test 4 ------------------------------------------------------------------
log "Test 4: Preflight verändert nichts"
PKGS_AFTER=$(vm "dpkg-query -W -f='\${Package} \${Version}\n' | sha256sum")
[[ $PKGS_BEFORE == "$PKGS_AFTER" ]] && pass "Paketliste unverändert" || fail "Paketliste verändert"
CHANGED=$(vm 'sudo find /etc /usr /opt /boot /root /var/lib -xdev -type f -newer /root/.pf-marker \
    ! -path "/var/lib/apt/*" ! -path "/var/lib/systemd/*" ! -path "/var/lib/dhcp/*" \
    ! -path "/var/lib/cloud/*" ! -path "/var/lib/sudo/*" ! -path "/var/lib/private/*" \
    ! -path "/var/lib/chrony/*" ! -path "/var/lib/logrotate/*" ! -path "/var/lib/dpkg/*" \
    ! -path "/root/.pf-marker" 2>/dev/null' || true)
[[ -z $CHANGED ]] && pass "keine Dateien verändert" || fail "veränderte Dateien: $CHANGED"
vm 'test ! -e /var/lib/siem && test ! -e /opt/siem' && pass "kein Zustandsverzeichnis angelegt" \
    || fail "Zustands-/Installationsverzeichnis angelegt"
vm 'sudo test -b /dev/vdb && [ "$(sudo lsblk -npo NAME /dev/vdb | wc -l)" -eq 1 ]' \
    && pass "Daten-Disk unberührt" || fail "Daten-Disk verändert"

# --- Test 5 ------------------------------------------------------------------
log "Test 5: unbeaufsichtigte Installation der Host-Schritte"
vm 'cat > ~/antworten.env' <<EOF
SIEM_LANG=de
SIEM_FQDN=siem.test.local
SIEM_NTP=0.debian.pool.ntp.org,1.debian.pool.ntp.org
SIEM_DATA_DISK=/dev/vdb
SIEM_DATA_DISK_CONFIRM=yes
SIEM_ADMIN_SSH_KEY="$(cat id_ed25519.pub)"
SIEM_ADMIN_PASSWORD_FILE=/home/install/pw1
SIEM_WEB_ADMIN_PASSWORD_FILE=/home/install/pw2
SIEM_SSH_PASSWORD_AUTH=no
SIEM_ACCEPT_WARNINGS=yes
EOF
printf '%s\n' "$ADMIN_PW" | vm 'cat > ~/pw1'
printf '%s\n' "Kennwort-fuer-webadmin-1" | vm 'cat > ~/pw2'
set +e
OUT=$(vm "sudo env NO_COLOR=1 ${LOW[*]} bash ~/siem/host/install.sh --unattended ~/antworten.env" 2>&1)
RC=$?
set -e
printf '%s\n' "$OUT" | tail -40
if [[ $RC -eq 0 ]]; then pass "Installation vollständig (Exit 0)"
else fail "Exit 0 erwartet, erhalten $RC"; printf '%s\n' "$OUT"; vm 'sudo tail -80 /var/log/siem-install.log' || true; fi
expect "Installation abgeschlossen" "Abschlusszusammenfassung ausgegeben"
expect "Selbsttest bestanden" "Selbsttest der Installation bestanden"
expect "Syslog TCP: Testereignis nach" "Selbsttest: Syslog TCP Ende-zu-Ende"
expect "Syslog UDP: Testereignis nach" "Selbsttest: Syslog UDP Ende-zu-Ende"
expect "Syslog TLS: Testereignis nach" "Selbsttest: Syslog TLS Ende-zu-Ende"
expect "Integritätsüberwachung aktiv" "Selbsttest: AIDE/rkhunter eingerichtet"
expect "Lynis-Härtungsindex: [0-9]+" "Selbsttest meldet Lynis-Härtungsindex"

# Ab hier: Zugang nur noch als siemadmin mit Schlüssel
if vm true 2>/dev/null; then fail "Installationsbenutzer hat noch SSH-Zugang"; else pass "Installationsbenutzer ohne SSH-Zugang"; fi
VM_USER=siemadmin
if vm true; then pass "SSH als siemadmin mit Schlüssel"; else fail "SSH als siemadmin nicht möglich"; exit 1; fi
check "sudo für siemadmin mit Kennwort" 'true'

# Zustand
for s in questions base datadisk hardening docker firewall hostd app selftest; do
    check "Zustand: $s done" "grep -q '^$s done' /var/lib/siem/install.state"
done
check "Zustand: keine offenen Schritte" "! grep -qvE ' done ' /var/lib/siem/install.state"
check "Geheimnis siemadmin verbraucht und gelöscht" 'test ! -e /var/lib/siem/secrets/admin_password'
check "Geheimnis Web-Admin bleibt bis zur Web-UI (Phase 2)" '[ "$(cat /var/lib/siem/secrets/web_admin_password)" = "Kennwort-fuer-webadmin-1" ]'

# Basis
check "Pakete installiert" 'dpkg-query -W nftables chrony auditd aide lvm2 unattended-upgrades lynis jq >/dev/null'
check "Installer nach /opt/siem/host kopiert" 'test -x /opt/siem/host/install.sh && test -f /opt/siem/VERSION'

# Daten-Disk
check "LVM siem/data auf /dev/vdb" 'lvs siem/data >/dev/null && pvs --noheadings -o pv_name | grep -q /dev/vdb'
check "Daten-Disk eingehängt mit nodev,nosuid,noexec" 'o=$(findmnt -no OPTIONS /opt/siem/data); [[ $o == *nodev* && $o == *nosuid* && $o == *noexec* ]]'
check "genau ein fstab-Eintrag" '[ "$(grep -c " /opt/siem/data " /etc/fstab)" -eq 1 ]'
check "Verzeichnisstruktur und Backups-Link" 'test -d /opt/siem/data/opensearch && test -L /opt/siem/backups && [ "$(stat -c %a /opt/siem/data/secrets)" = 700 ]'

# Härtung
check "sysctl: Kernel-Härtung aktiv" '[ "$(sysctl -n kernel.kptr_restrict)" = 2 ] && [ "$(sysctl -n net.ipv4.tcp_syncookies)" = 1 ] && [ "$(sysctl -n net.ipv4.conf.all.accept_redirects)" = 0 ]'
check "sysctl: OpenSearch vm.max_map_count" '[ "$(sysctl -n vm.max_map_count)" = 262144 ]'
check "Module gesperrt (usb-storage)" 'modprobe -n -v usb-storage 2>&1 | grep -q "/bin/false"'
check "SSH: root-Login aus" 'sshd -T | grep -qx "permitrootlogin no"'
check "SSH: Kennwort-Anmeldung aus" 'sshd -T | grep -qx "passwordauthentication no"'
check "SSH: nur Gruppe siem-ssh" 'sshd -T | grep -qx "allowgroups siem-ssh"'
check "SSH: MaxAuthTries 3" 'sshd -T | grep -qx "maxauthtries 3"'
check "auditd aktiv mit SIEM-Regeln" 'systemctl is-active --quiet auditd && auditctl -l | grep -q "/etc/shadow -p wa -k identity" && auditctl -l | grep -q "key=time-change"'
check "chrony mit konfigurierten Servern" 'grep -q "0.debian.pool.ntp.org" /etc/chrony/sources.d/siem.sources && ! grep -qE "^pool " /etc/chrony/chrony.conf && systemctl is-active --quiet chrony'
check "Automatische Sicherheitsupdates" 'grep -q "Unattended-Upgrade \"1\"" /etc/apt/apt.conf.d/20auto-upgrades'

# Docker
check "Docker läuft" 'docker info >/dev/null && docker compose version >/dev/null'
check "Docker: live-restore, kein docker0" 'docker info --format "{{.LiveRestoreEnabled}}" | grep -q true && ! ip link show docker0 >/dev/null 2>&1'

# Firewall
check "nftables: Tabelle inet siem geladen" 'nft list table inet siem >/dev/null'
check "nftables: Dienst aktiv, Drop-in vorhanden" 'systemctl is-enabled --quiet nftables && test -f /etc/systemd/system/nftables.service.d/siem.conf'
check "nftables: input policy drop" 'nft list chain inet siem input | grep -q "policy drop"'

# Wirksamkeit: 443 (freigegeben, Umleitung auf Proxy 8443), 8081 (nicht freigegeben),
# 8443 direkt (nur über die Umleitung erlaubt)
web() { curl -sk -o /dev/null --max-time 5 "https://127.0.0.1:$1/health"; }
vmr 'cd /tmp && { setsid python3 -m http.server 8081 >/dev/null 2>&1 & } ; sleep 2' || true
if web 8443; then pass "443 aus freigegebenem Netz erreichbar (Proxy)"; else fail "443 nicht erreichbar"; fi
if curl -s -o /dev/null --max-time 5 http://127.0.0.1:8081/; then fail "nicht freigegebener Port 8081 erreichbar"; else pass "nicht freigegebener Port 8081 blockiert"; fi
if web 9443; then fail "interner Port 8443 direkt erreichbar"; else pass "interner Port 8443 nur über die Umleitung erreichbar"; fi
vmr 'nft delete element inet siem allow_https "{ 10.0.0.0/8 }"' || true
if web 8443; then fail "443 trotz entfernter Freigabe erreichbar"; else pass "443 nach Entfernen der Freigabe blockiert"; fi
vmr 'nft -f /etc/nftables.conf; pkill -f "http.server" || true' || true
if vm true; then pass "SSH nach Neuladen der Firewall weiterhin möglich"; else fail "SSH nach Neuladen der Firewall verloren"; exit 1; fi
check "Docker-Regeln nach Neuladen der Firewall erhalten" 'nft list tables | grep -vq "inet siem"'

# --- Test 6 ------------------------------------------------------------------
log "Test 6: Idempotenz – erneuter Lauf aller Host-Schritte"
FILES="/opt/siem/data/app/app.env /opt/siem/data/secrets/vector/secrets.json /opt/siem/data/app/opensearch-security/internal_users.yml /opt/siem/data/secrets/pki/web.crt /opt/siem/data/secrets/pki/ca.crt /opt/siem/data/secrets/opensearch-admin.pw /etc/systemd/system/siem-hostd.service /usr/local/sbin/siem-hostd /opt/siem/data/hostd/firewall.json /etc/fstab /etc/nftables.conf /etc/ssh/sshd_config.d/00-siem.conf /etc/docker/daemon.json /etc/sysctl.d/99-siem-hardening.conf /etc/chrony/sources.d/siem.sources /etc/chrony/chrony.conf /etc/audit/rules.d/50-siem.rules /etc/modprobe.d/siem-blacklist.conf /etc/apt/sources.list.d/docker.sources"
SUM_BEFORE=$(vmr "sha256sum $FILES")
CID_BEFORE=$(vmr 'docker ps -q --no-trunc | sort')
vmr 'sed -i -E "s/^(base|datadisk|hardening|docker|firewall|hostd|app|selftest) done/\1 pending/" /var/lib/siem/install.state'
set +e
OUT=$(vmr "env NO_COLOR=1 ${LOW[*]} bash /opt/siem/host/install.sh --resume </dev/null" 2>&1)
RC=$?
set -e
printf '%s\n' "$OUT" | tail -25
if [[ $RC -eq 0 ]]; then pass "erneuter Lauf aller Schritte: Exit 0"; else fail "erneuter Lauf: Exit 0 erwartet, erhalten $RC"; printf '%s\n' "$OUT"; fi
if grep -q 'Installationsfragen' <<<"$OUT"; then fail "Resume stellt Fragen erneut"; else pass "keine erneuten Fragen"; fi
SUM_AFTER=$(vmr "sha256sum $FILES")
if [[ $SUM_BEFORE == "$SUM_AFTER" ]]; then pass "Konfigurationsdateien unverändert"
else fail "Konfiguration verändert:"; diff <(echo "$SUM_BEFORE") <(echo "$SUM_AFTER") || true; fi
CID_AFTER=$(vmr 'docker ps -q --no-trunc | sort')
if [[ $CID_BEFORE == "$CID_AFTER" ]]; then pass "Container nicht neu erzeugt"; else fail "Container wurden neu erzeugt"; fi
check "weiterhin genau ein LV und ein fstab-Eintrag" '[ "$(lvs --noheadings siem | wc -l)" -eq 1 ] && [ "$(grep -c " /opt/siem/data " /etc/fstab)" -eq 1 ]'
check "Daten weiterhin eingehängt" 'findmnt /opt/siem/data >/dev/null'
if vm true; then pass "SSH weiterhin möglich"; else fail "SSH nach erneutem Lauf verloren"; fi

# --- Test 7 ------------------------------------------------------------------
log "Test 7: Preflight nach Teilinstallation"
set +e
OUT=$(vmr "env NO_COLOR=1 ${LOW[*]} bash /opt/siem/host/install.sh --preflight" 2>&1)
RC=$?
set -e
printf '%s\n' "$OUT"
[[ $RC -le 1 ]] && pass "keine Fehler durch eigene Änderungen (Exit $RC)" || fail "Preflight meldet Fehler (Exit $RC)"
expect 'Daten-Disk +bereits eingerichtet \(/dev/vdb' "Daten-Disk als eingerichtet erkannt"
expect 'Container-Laufzeit +durch SIEM-Installation' "Docker als eigene Installation erkannt"

# --- Test 8 ------------------------------------------------------------------
log "Test 8: siem-hostd und Dead-Man's-Switch"
reach() { curl -sk -o /dev/null --max-time 5 https://127.0.0.1:8443/health; }
check "siem-hostd aktiv" 'systemctl is-active --quiet siem-hostd'
check "Socket root:siem-hostd 0660" '[ "$(stat -c "%U:%G %a" /run/siem/hostd.sock)" = "root:siem-hostd 660" ]'
check "Systemstatus über den Socket" 'siem-hostd system status | jq -e ".version and .services.docker == \"active\"" >/dev/null'
if vm '/usr/local/sbin/siem-hostd system status' >/dev/null 2>&1; then fail "Socket ohne Gruppenrecht nutzbar"
else pass "kein Socket-Zugriff ohne Gruppe siem-hostd"; fi
check "unbekannte Aktion wird abgelehnt" 'python3 -c "import socket; s = socket.socket(socket.AF_UNIX); s.connect(\"/run/siem/hostd.sock\"); s.sendall(b\"{\\\"action\\\": \\\"shell.exec\\\"}\\n\"); print(s.recv(4096).decode())" | grep -q "Unbekannte Aktion"'
check "ungültige Freigabe abgelehnt, nichts ausstehend" 'echo "{\"services\": {\"https\": {\"sources\": [\"10.0.0.0/33\"]}}}" > /tmp/bad.json; ! siem-hostd firewall apply --file /tmp/bad.json --no-wait 2>/dev/null && siem-hostd firewall show | jq -e ".pending == null" >/dev/null'

vmr 'siem-hostd firewall show | jq ".committed | .services.https.sources = []" > /tmp/fw-nohttps.json
     siem-hostd firewall show | jq ".committed | .services.ssh.sources = [\"192.0.2.1/32\"]" > /tmp/fw-nossh.json
     siem-hostd firewall show | jq ".committed" > /tmp/fw-orig.json'
if reach; then pass "443 vor der Änderung erreichbar"; else fail "443 vor der Änderung nicht erreichbar"; fi

# 8a: ohne Bestätigung → automatische Rücknahme
TOKEN=$(vmr 'siem-hostd firewall apply --file /tmp/fw-nohttps.json --no-wait' | jq -r .token)
[[ -n $TOKEN && $TOKEN != null ]] && pass "apply liefert Bestätigungs-Token" || fail "kein Token"
if reach; then fail "443 trotz entzogener Freigabe erreichbar"; else pass "Änderung sofort aktiv (443 gesperrt)"; fi
check "unbestätigte Änderung nicht dauerhaft gespeichert" 'grep -q "set allow_https { type ipv4_addr; flags interval; auto-merge; elements" /etc/nftables.conf'
sleep 70
if reach; then pass "Dead-Man's-Switch: Regeln nach 60 s automatisch zurückgesetzt"; else fail "keine automatische Rücknahme"; fi
check "keine ausstehende Änderung mehr" 'siem-hostd firewall show | jq -e ".pending == null" >/dev/null'
check "Rücknahme im Audit-Log" 'grep -q "Dead-Man" /var/log/siem-hostd.log'

# 8b: mit Bestätigung → dauerhaft
TOKEN=$(vmr 'siem-hostd firewall apply --file /tmp/fw-nohttps.json --no-wait' | jq -r .token)
check "falsches Token abgelehnt" '! siem-hostd firewall confirm falsches-token 2>/dev/null'
check "Bestätigung mit Token" "siem-hostd firewall confirm $TOKEN >/dev/null"
sleep 65
if reach; then fail "bestätigte Änderung wurde zurückgesetzt"; else pass "bestätigte Änderung bleibt nach Fristablauf aktiv"; fi
check "bestätigte Änderung dauerhaft in nftables.conf" '! grep -q "set allow_https { type ipv4_addr; flags interval; auto-merge; elements" /etc/nftables.conf'
check "Neustart von nftables: eigene Regeln geladen, Docker-Tabellen erhalten" 'systemctl restart nftables && ! nft list set inet siem allow_https | grep -q elements && nft list tables | grep -v "inet siem" | grep -q table'
check "Ausgangszustand wiederherstellen" 't=$(siem-hostd firewall apply --file /tmp/fw-orig.json --no-wait | jq -r .token) && siem-hostd firewall confirm "$t" >/dev/null'
if reach; then pass "443 wieder erreichbar"; else fail "443 nach Wiederherstellung nicht erreichbar"; fi

# 8c: sich selbst aussperren → automatische Rücknahme
vmr 'siem-hostd firewall apply --file /tmp/fw-nossh.json --no-wait >/dev/null' || true
if vm true 2>/dev/null; then fail "neue SSH-Verbindung trotz entzogener Freigabe möglich"; else pass "Aussperren simuliert: neue SSH-Verbindung blockiert"; fi
sleep 60
if vm true; then pass "Dead-Man's-Switch: SSH nach Fristablauf wieder möglich"; else fail "SSH bleibt gesperrt"; exit 1; fi

# 8d: Neustart von siem-hostd während der Frist
vmr 'siem-hostd firewall apply --file /tmp/fw-nohttps.json --no-wait >/dev/null; systemctl restart siem-hostd' || true
if reach; then fail "Änderung nach Neustart nicht aktiv"; else pass "Änderung aktiv, siem-hostd neu gestartet"; fi
sleep 70
if reach; then pass "Rücknahme auch nach Neustart von siem-hostd"; else fail "keine Rücknahme nach Neustart"; fi
vmr 'pkill -f "http.server" || true' || true

# --- Test 9 ------------------------------------------------------------------
log "Test 9: Anwendung – Ingest Ende-zu-Ende, OpenSearch, Proxy, Disk-Puffer"
OSI='python3 /opt/siem/app/current/opensearch/init.py --ca /opt/siem/data/secrets/pki/ca.crt --password-file /opt/siem/data/secrets/opensearch-admin.pw'
check "Container laufen (opensearch, vector, proxy)" 'for c in siem-opensearch siem-vector siem-proxy; do [ "$(docker inspect -f "{{.State.Status}}" $c)" = running ] || exit 1; done'
check "Images per Digest festgeschrieben" 'for c in siem-opensearch siem-vector siem-proxy; do docker inspect -f "{{.Config.Image}}" $c | grep -q "@sha256:" || exit 1; done'
check "OpenSearch nur auf 127.0.0.1" '! ss -Hltn | awk "{print \$4}" | grep -E ":(9200|9300)$" | grep -vqE "^(\[::ffff:)?127\.0\.0\.1\]?:"'
check "OpenSearch ohne Anmeldung abgewiesen (401)" '[ "$(curl -s -o /dev/null -w "%{http_code}" --cacert /opt/siem/data/secrets/pki/ca.crt https://127.0.0.1:9200/)" = 401 ]'
check "11 Index-Templates und 11 ISM-Richtlinien" "$OSI show | jq -e '(.templates|length)==11 and ([.policies[]|select(startswith(\"siem-\"))]|length)==11' >/dev/null"
check "Vector-Benutzer darf keine Indizes löschen (403)" 'pw=$(cat /opt/siem/data/secrets/vector.pw); [ "$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -u vector:$pw --cacert /opt/siem/data/secrets/pki/ca.crt https://127.0.0.1:9200/siem-system-$(date -u +%Y.%m.%d))" = 403 ]'
check "Kompression zstd oder best_compression im Template" "pw=\$(cat /opt/siem/data/secrets/opensearch-admin.pw); curl -s -u admin:\$pw --cacert /opt/siem/data/secrets/pki/ca.crt https://127.0.0.1:9200/_index_template/siem-firewall | jq -e '.index_templates[0].index_template.template.settings.index.codec | test(\"zstd|best_compression\")' >/dev/null"

TAG="vmtest-$RANDOM$RANDOM"
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
send_udp() { printf '%s\n' "$1" >/dev/udp/127.0.0.1/5514; }
send_tcp() { timeout 5 bash -c 'printf "%s\n" "$1" >/dev/tcp/127.0.0.1/5514' _ "$1"; }
found() { vmr "$OSI find --index 'siem-unparsed-*' --text '$1' --timeout ${2:-15}" >/dev/null 2>&1; }

send_udp "<14>1 $(ts) fgt-test test-app - - - ${TAG}-udp"
send_tcp "<14>1 $(ts) fgt-test test-app - - - ${TAG}-tcp" || true
if found "${TAG}-udp"; then pass "Syslog UDP 514 von extern in OpenSearch"; else fail "Syslog UDP 514 nicht angekommen"; fi
if found "${TAG}-tcp"; then pass "Syslog TCP 514 von extern in OpenSearch"; else fail "Syslog TCP 514 nicht angekommen"; fi
vmr 'cat /opt/siem/data/secrets/pki/ca.crt' > ca.crt
send_tls() {  # Verbindung 3 s offen halten, damit der Eintrag sicher übertragen ist
    { printf '<14>1 %s fgt-test test-app - - - %s\n' "$(ts)" "$1"; sleep 3; } \
        | timeout 15 openssl s_client -connect 127.0.0.1:6514 -quiet -CAfile ca.crt -verify_return_error >/dev/null 2>&1 || true
}
send_tls "${TAG}-tls"
found "${TAG}-tls" || send_tls "${TAG}-tls"   # einmalige Wiederholung (Verbindungsaufbau über QEMU-Weiterleitung)
if found "${TAG}-tls"; then pass "Syslog TLS 6514 von extern in OpenSearch (Zertifikat geprüft)"; else fail "Syslog TLS 6514 nicht angekommen"; fi

FIELDS=$(vmr "pw=\$(cat /opt/siem/data/secrets/opensearch-admin.pw); curl -s -u admin:\$pw --cacert /opt/siem/data/secrets/pki/ca.crt -H 'Content-Type: application/json' 'https://127.0.0.1:9200/siem-unparsed-*/_search' -d '{\"query\":{\"match_phrase\":{\"message\":\"${TAG}-udp\"}}}'")
if jq -e '.hits.hits[0]._source | (.observer.ip|type=="string") and .siem.category=="unparsed" and (.["@timestamp"]|type=="string") and .event.dataset=="syslog.generic" and .host.hostname=="fgt-test"' <<<"$FIELDS" >/dev/null; then
    pass "ECS-Felder gesetzt (@timestamp, observer.ip, host.hostname, event.dataset, siem.category)"
else fail "ECS-Felder unvollständig: $(head -c 600 <<<"$FIELDS")"; fi

# Firewall: Syslog aus nicht freigegebenem Netz wird verworfen
vmr 'siem-hostd firewall show | jq ".committed | .services.syslog.sources = []" > /tmp/fw-nosyslog.json
     t=$(siem-hostd firewall apply --file /tmp/fw-nosyslog.json --no-wait | jq -r .token); siem-hostd firewall confirm "$t" >/dev/null'
send_udp "<14>1 $(ts) fgt-test test-app - - - ${TAG}-blocked-udp"
send_tcp "<14>1 $(ts) fgt-test test-app - - - ${TAG}-blocked-tcp" || true
if found "${TAG}-blocked-udp" 8; then fail "Syslog UDP trotz fehlender Freigabe angenommen"; else pass "Syslog UDP aus nicht freigegebenem Netz verworfen"; fi
if found "${TAG}-blocked-tcp" 2; then fail "Syslog TCP trotz fehlender Freigabe angenommen"; else pass "Syslog TCP aus nicht freigegebenem Netz verworfen"; fi
vmr 't=$(siem-hostd firewall apply --file /tmp/fw-orig.json --no-wait | jq -r .token); siem-hostd firewall confirm "$t" >/dev/null'
send_udp "<14>1 $(ts) fgt-test test-app - - - ${TAG}-again"
if found "${TAG}-again"; then pass "nach erneuter Freigabe wieder angenommen"; else fail "nach erneuter Freigabe nicht angenommen"; fi

# Proxy
if curl -sk --max-time 5 https://127.0.0.1:8443/health | grep -q '"status":"ok"'; then pass "/health über 443"; else fail "/health über 443"; fi
if curl -s --max-time 5 --cacert ca.crt --resolve siem.test.local:8443:127.0.0.1 https://siem.test.local:8443/health >/dev/null; then
    pass "Web-Zertifikat der Appliance-CA gültig für den FQDN"; else fail "Web-Zertifikat nicht gültig"; fi
H=$(curl -sk -D - -o /dev/null --max-time 5 https://127.0.0.1:8443/)
if grep -qi '^strict-transport-security:' <<<"$H" && grep -qi '^content-security-policy:' <<<"$H" \
    && grep -qi '^x-frame-options: DENY' <<<"$H" && grep -qi '^x-content-type-options: nosniff' <<<"$H"; then
    pass "Sicherheits-Header (HSTS, CSP, X-Frame-Options, nosniff)"; else fail "Sicherheits-Header fehlen: $H"; fi
if grep -qi '^server:' <<<"$H"; then fail "Server-Header wird gesendet"; else pass "kein Server-Header"; fi
if curl -sk --tls-max 1.2 -o /dev/null --max-time 5 https://127.0.0.1:8443/health; then fail "TLS 1.2 akzeptiert"; else pass "nur TLS 1.3"; fi
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 --get --data-urlencode 'q=<script>alert(1)</script>' https://127.0.0.1:8443/)
if [[ $CODE == 403 ]]; then pass "WAF (ModSecurity + OWASP CRS) blockiert XSS-Versuch (403)"; else fail "WAF hat XSS-Versuch nicht blockiert (HTTP $CODE)"; fi

# Disk-Puffer: OpenSearch aus, 500 Ereignisse, Vector-Neustart, OpenSearch an → alle da
vmr 'docker stop siem-opensearch >/dev/null'
vmr "exec 3<>/dev/tcp/127.0.0.1/10514; for i in \$(seq 1 500); do printf '<14>1 %s siem buf-test - - - ${TAG}-buffer %d\n' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \$i >&3; done; exec 3>&-"
sleep 5
vmr 'docker restart siem-vector >/dev/null; sleep 5; docker start siem-opensearch >/dev/null'
vmr "$OSI wait --timeout 300 >/dev/null" || true
N=0
for _ in $(seq 1 40); do
    N=$(vmr "$OSI count --index 'siem-unparsed-*' --text '${TAG}-buffer'" 2>/dev/null || echo 0)
    [[ $N =~ ^[0-9]+$ ]] || N=0
    (( N >= 500 )) && break
    sleep 3
done
if (( N >= 500 )); then pass "Disk-Puffer: $N/500 Ereignisse nach Vector-Neustart bei ausgefallenem OpenSearch"
else fail "Disk-Puffer: nur $N/500 Ereignisse angekommen"; fi

# --- Test 10 -----------------------------------------------------------------
log "Test 10: Integrität, Lynis, ergänzende Härtung, --repair"
check "AIDE-Datenbank initialisiert" 'test -s /var/lib/aide/aide.db'
check "AIDE: tägliche Prüfung aktiv" 'systemctl is-enabled --quiet dailyaidecheck.timer'
check "AIDE: Prüfung ohne Abweichungen bei veränderlichen Daten" 'aide --check --config /etc/aide/aide.conf >/tmp/aide.out 2>&1; rc=$?; [ $rc -lt 8 ] || { tail -30 /tmp/aide.out; false; }'
check "rkhunter-Datenbank vorhanden" 'test -s /var/lib/rkhunter/db/rkhunter.dat'
check "Anmelde-Banner (SSH)" 'sshd -T | grep -qx "banner /etc/issue.net" && grep -q "Authorized access only" /etc/issue.net'
check "SSH: MaxSessions 2, keine Kompression" 'sshd -T | grep -qx "maxsessions 2" && sshd -T | grep -qx "compression no"'
check "Core-Dumps deaktiviert" 'grep -q "hard *core *0" /etc/security/limits.d/90-siem.conf && grep -q "^Storage=none" /etc/systemd/coredump.conf.d/90-siem.conf'
check "login.defs: UMASK 027" 'grep -qE "^UMASK[[:space:]]+027$" /etc/login.defs'
check "Prozess-Accounting aktiv" 'systemctl is-active --quiet acct'
LYNIS=$(vmr "awk -F= '/^hardening_index=/ { print \$2 }' /var/log/lynis-report.dat" || true)
if [[ $LYNIS =~ ^[0-9]+$ ]] && (( LYNIS >= 80 )); then pass "Lynis-Härtungsindex $LYNIS ≥ 80"
else fail "Lynis-Härtungsindex ${LYNIS:-unbekannt} < 80"; vmr "grep -E '^(warning|suggestion)\[\]=' /var/log/lynis-report.dat" || true; fi

# Abweichungen vom Sollzustand erzeugen, dann --repair
DOCS_BEFORE=$(vmr "$OSI count --index 'siem-unparsed-*' --text '${TAG}'" 2>/dev/null || echo 0)
vmr 'rm -f /etc/ssh/sshd_config.d/00-siem.conf /etc/modprobe.d/siem-blacklist.conf
     sysctl -qw kernel.kptr_restrict=0
     sed -i "s/^UMASK.*/UMASK\t\t022/" /etc/login.defs
     docker stop siem-vector >/dev/null'
set +e
OUT=$(vmr "env NO_COLOR=1 ${LOW[*]} bash /opt/siem/host/install.sh --repair </dev/null" 2>&1)
RC=$?
set -e
printf '%s\n' "$OUT" | tail -25
if [[ $RC -eq 0 ]]; then pass "--repair: Exit 0"; else fail "--repair: Exit 0 erwartet, erhalten $RC"; printf '%s\n' "$OUT"; fi
expect "Reparatur" "Reparatur angekündigt"
if grep -q 'Installationsfragen' <<<"$OUT"; then fail "--repair stellt Fragen"; else pass "--repair ohne Fragen"; fi
check "--repair: SSH-Drop-in wiederhergestellt" 'test -f /etc/ssh/sshd_config.d/00-siem.conf && sshd -T | grep -qx "permitrootlogin no"'
check "--repair: Modulsperren wiederhergestellt" 'test -f /etc/modprobe.d/siem-blacklist.conf'
check "--repair: sysctl wiederhergestellt" '[ "$(sysctl -n kernel.kptr_restrict)" = 2 ]'
check "--repair: UMASK wiederhergestellt" 'grep -qE "^UMASK[[:space:]]+027$" /etc/login.defs'
check "--repair: Vector läuft wieder" '[ "$(docker inspect -f "{{.State.Status}}" siem-vector)" = running ]'
check "--repair: Zustand vollständig" '! grep -qvE " done " /var/lib/siem/install.state'
DOCS_AFTER=$(vmr "$OSI count --index 'siem-unparsed-*' --text '${TAG}'" 2>/dev/null || echo 0)
if [[ $DOCS_BEFORE =~ ^[0-9]+$ ]] && (( DOCS_AFTER >= DOCS_BEFORE && DOCS_BEFORE > 0 )); then
    pass "--repair: Ereignisse erhalten ($DOCS_AFTER)"; else fail "--repair: Ereignisse vorher $DOCS_BEFORE, nachher $DOCS_AFTER"; fi
if vm true; then pass "SSH nach --repair weiterhin möglich"; else fail "SSH nach --repair verloren"; exit 1; fi

finish "$DIAG
echo \"--- Indizes\"; pw=\$(cat /opt/siem/data/secrets/opensearch-admin.pw); curl -s -u admin:\$pw --cacert /opt/siem/data/secrets/pki/ca.crt \"https://127.0.0.1:9200/_cat/indices?v\"
echo \"--- nft prerouting\"; nft list chain inet siem prerouting"
