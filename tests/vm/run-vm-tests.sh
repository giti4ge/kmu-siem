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
#
# Umgebungsvariablen: VM_RAM_MB (4096), VM_CPUS (2), WORKDIR (./.vm), DEBIAN_IMAGE_URL
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
WORKDIR=${WORKDIR:-$REPO/.vm}
VM_RAM_MB=${VM_RAM_MB:-4096}
VM_CPUS=${VM_CPUS:-2}
DEBIAN_IMAGE_URL=${DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}
SSH_PORT=2222
FAILED=0

log()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
pass() { printf '\033[32mOK\033[0m   %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }

mkdir -p "$WORKDIR"
cd "$WORKDIR"

# --- VM vorbereiten ----------------------------------------------------------
log "Debian-13-Cloud-Image"
[[ -f base.qcow2 ]] || curl -fsSL -o base.qcow2 "$DEBIAN_IMAGE_URL"
rm -f system.qcow2 data.qcow2 seed.img id_ed25519 id_ed25519.pub serial.log
qemu-img create -q -f qcow2 -F qcow2 -b base.qcow2 system.qcow2 40G
qemu-img create -q -f qcow2 data.qcow2 500G          # leer, sparse
ssh-keygen -q -t ed25519 -N '' -f id_ed25519 -C vm-test

cat >user-data <<EOF
#cloud-config
hostname: siem
fqdn: siem.test.local
manage_etc_hosts: true
users:
  - name: install
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat id_ed25519.pub)
EOF
printf 'instance-id: siem-vm-test\nlocal-hostname: siem\n' >meta-data
cloud-localds seed.img user-data meta-data

ACCEL=(-accel tcg)
BOOT_TIMEOUT=900
if [[ -w /dev/kvm ]]; then ACCEL=(-enable-kvm -cpu host); BOOT_TIMEOUT=300; else
    echo "WARNUNG: /dev/kvm nicht verfügbar – Software-Emulation (langsam)"; fi

log "VM starten (${VM_CPUS} vCPU, ${VM_RAM_MB} MB RAM, Disks 40G + 500G)"
qemu-system-x86_64 "${ACCEL[@]}" -m "$VM_RAM_MB" -smp "$VM_CPUS" \
    -drive file=system.qcow2,if=virtio \
    -drive file=data.qcow2,if=virtio \
    -drive file=seed.img,if=virtio,format=raw \
    -nic "user,model=virtio,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22,hostfwd=tcp:127.0.0.1:8443-:443,hostfwd=tcp:127.0.0.1:8080-:8080" \
    -display none -serial file:serial.log -daemonize -pidfile qemu.pid
trap 'kill "$(cat "$WORKDIR/qemu.pid" 2>/dev/null)" 2>/dev/null || true' EXIT

SSH=(ssh -i id_ed25519 -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes -o ServerAliveInterval=30)
VM_USER=install
ADMIN_PW="Kennwort-fuer-siemadmin-1"
vm() { "${SSH[@]}" "$VM_USER@127.0.0.1" "$@"; }

# vmr SKRIPT – als root in der VM ausführen (nach der Installation: siemadmin + sudo-Kennwort)
vmr() {
    if [[ $VM_USER == install ]]; then
        "${SSH[@]}" "$VM_USER@127.0.0.1" "sudo bash -s" <<<"$1"
    else
        printf '%s\n%s\n' "$ADMIN_PW" "$1" | "${SSH[@]}" "$VM_USER@127.0.0.1" "sudo -S -p '' bash -s"
    fi
}
# check BESCHREIBUNG ROOT-SKRIPT
check() { if vmr "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi; }
expect() { if grep -qE -- "$1" <<<"$OUT"; then pass "$2"; else fail "$2 (Muster: $1)"; fi; }

for (( t = 0; t < BOOT_TIMEOUT; t += 5 )); do
    vm true 2>/dev/null && break
    sleep 5
done
vm true || { tail -50 serial.log; echo "VM nicht erreichbar"; exit 1; }
vm 'cloud-init status --wait >/dev/null 2>&1 || true'
pass "VM erreichbar"

# Repository-Teile übertragen
tar -C "$REPO" -czf - host VERSION | vm 'mkdir -p ~/siem && tar -C ~/siem -xzf -'

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
LOW=(SIEM_MIN_CPU=1 SIEM_REC_CPU=1 SIEM_MIN_RAM_GB=2 SIEM_REC_RAM_GB=2)
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
if [[ $RC -eq 3 ]]; then pass "Exit 3 (nächster Schritt noch nicht implementiert)"
else fail "Exit 3 erwartet, erhalten $RC"; printf '%s\n' "$OUT"; vm 'sudo tail -80 /var/log/siem-install.log' || true; fi
expect "Schritt 'hostd' ist noch nicht implementiert" "Host-Schritte vollständig, Abbruch bei hostd"

# Ab hier: Zugang nur noch als siemadmin mit Schlüssel
if vm true 2>/dev/null; then fail "Installationsbenutzer hat noch SSH-Zugang"; else pass "Installationsbenutzer ohne SSH-Zugang"; fi
VM_USER=siemadmin
if vm true; then pass "SSH als siemadmin mit Schlüssel"; else fail "SSH als siemadmin nicht möglich"; exit 1; fi
check "sudo für siemadmin mit Kennwort" 'true'

# Zustand
for s in questions base datadisk hardening docker firewall; do
    check "Zustand: $s done" "grep -q '^$s done' /var/lib/siem/install.state"
done
check "Zustand: hostd pending" "grep -q '^hostd pending' /var/lib/siem/install.state"
check "Geheimnis siemadmin verbraucht und gelöscht" 'test ! -e /var/lib/siem/secrets/admin_password'
check "Geheimnis Web-Admin bleibt bis Schritt app" '[ "$(cat /var/lib/siem/secrets/web_admin_password)" = "Kennwort-fuer-webadmin-1" ]'

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

# Wirksamkeit: Testdienste auf 443 (freigegeben) und 8080 (nicht freigegeben)
vmr 'cd /tmp && { setsid python3 -m http.server 443 >/dev/null 2>&1 & } ; { setsid python3 -m http.server 8080 >/dev/null 2>&1 & } ; sleep 2' || true
if curl -s -o /dev/null --max-time 5 http://127.0.0.1:8443/; then pass "Port 443 aus freigegebenem Netz erreichbar"; else fail "Port 443 nicht erreichbar"; fi
if curl -s -o /dev/null --max-time 5 http://127.0.0.1:8080/; then fail "nicht freigegebener Port 8080 erreichbar"; else pass "nicht freigegebener Port 8080 blockiert"; fi
vmr 'nft delete element inet siem allow_https "{ 10.0.0.0/8 }"' || true
if curl -s -o /dev/null --max-time 5 http://127.0.0.1:8443/; then fail "443 trotz entfernter Freigabe erreichbar"; else pass "443 nach Entfernen der Freigabe blockiert"; fi
vmr 'nft -f /etc/nftables.conf; pkill -f "http.server" || true' || true
if vm true; then pass "SSH nach Neuladen der Firewall weiterhin möglich"; else fail "SSH nach Neuladen der Firewall verloren"; exit 1; fi
check "Docker-Regeln nach Neuladen der Firewall erhalten" 'nft list tables | grep -vq "inet siem"'

# --- Test 6 ------------------------------------------------------------------
log "Test 6: Idempotenz – erneuter Lauf aller Host-Schritte"
FILES="/etc/fstab /etc/nftables.conf /etc/ssh/sshd_config.d/00-siem.conf /etc/docker/daemon.json /etc/sysctl.d/99-siem-hardening.conf /etc/chrony/sources.d/siem.sources /etc/chrony/chrony.conf /etc/audit/rules.d/50-siem.rules /etc/modprobe.d/siem-blacklist.conf /etc/apt/sources.list.d/docker.sources"
SUM_BEFORE=$(vmr "sha256sum $FILES")
vmr 'sed -i -E "s/^(base|datadisk|hardening|docker|firewall) done/\1 pending/" /var/lib/siem/install.state'
set +e
OUT=$(vmr "env NO_COLOR=1 ${LOW[*]} bash /opt/siem/host/install.sh --resume </dev/null" 2>&1)
RC=$?
set -e
printf '%s\n' "$OUT" | tail -25
if [[ $RC -eq 3 ]]; then pass "erneuter Lauf: Exit 3 bei hostd"; else fail "erneuter Lauf: Exit 3 erwartet, erhalten $RC"; printf '%s\n' "$OUT"; fi
if grep -q 'Installationsfragen' <<<"$OUT"; then fail "Resume stellt Fragen erneut"; else pass "keine erneuten Fragen"; fi
SUM_AFTER=$(vmr "sha256sum $FILES")
if [[ $SUM_BEFORE == "$SUM_AFTER" ]]; then pass "Konfigurationsdateien unverändert"
else fail "Konfiguration verändert:"; diff <(echo "$SUM_BEFORE") <(echo "$SUM_AFTER") || true; fi
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
expect 'Daten-Disk +bereits eingerichtet (/dev/vdb' "Daten-Disk als eingerichtet erkannt"
expect 'Container-Laufzeit +durch SIEM-Installation' "Docker als eigene Installation erkannt"

log "Ergebnis"
if (( FAILED )); then echo "VM-Tests FEHLGESCHLAGEN"; exit 1; fi
echo "Alle VM-Tests bestanden."
