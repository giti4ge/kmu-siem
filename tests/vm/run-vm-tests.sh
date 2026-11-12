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
#   5. Unbeaufsichtigte Installation: Antworten werden übernommen, Zustand und
#      Rechte korrekt, Abbruch am ersten noch nicht implementierten Schritt (Exit 3)
#   6. --resume setzt am offenen Schritt fort
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
    -nic user,model=virtio,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22 \
    -display none -serial file:serial.log -daemonize -pidfile qemu.pid
trap 'kill "$(cat "$WORKDIR/qemu.pid" 2>/dev/null)" 2>/dev/null || true' EXIT

SSH=(ssh -i id_ed25519 -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o LogLevel=ERROR -o ConnectTimeout=5 install@127.0.0.1)
vm() { "${SSH[@]}" "$@"; }

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
expect() { if grep -qE -- "$1" <<<"$OUT"; then pass "$2"; else fail "$2 (Muster: $1)"; fi; }

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
log "Test 5: unbeaufsichtigte Installation (bis zum ersten offenen Schritt)"
vm 'cat > ~/antworten.env' <<EOF
SIEM_LANG=de
SIEM_FQDN=siem.test.local
SIEM_NTP=0.debian.pool.ntp.org,1.debian.pool.ntp.org
SIEM_DATA_DISK=/dev/vdb
SIEM_DATA_DISK_CONFIRM=yes
SIEM_ADMIN_SSH_KEY="$(cat id_ed25519.pub)"
SIEM_ADMIN_PASSWORD_FILE=/home/install/pw1
SIEM_WEB_ADMIN_PASSWORD_FILE=/home/install/pw2
SIEM_ACCEPT_WARNINGS=yes
EOF
vm 'printf "Kennwort-fuer-siemadmin-1\n" > ~/pw1; printf "Kennwort-fuer-webadmin-1\n" > ~/pw2'
set +e
OUT=$(vm "sudo env NO_COLOR=1 ${LOW[*]} bash ~/siem/host/install.sh --unattended ~/antworten.env" 2>&1)
RC=$?
set -e
printf '%s\n' "$OUT"
[[ $RC -eq 3 ]] && pass "Exit 3 (nächster Schritt noch nicht implementiert)" || fail "Exit 3 erwartet, erhalten $RC"
expect "Schritt 'base' ist noch nicht implementiert" "Abbruch bei Schritt base"
vm 'sudo grep -q "^questions done" /var/lib/siem/install.state' && pass "Zustand: questions done" || fail "Zustand questions fehlt"
vm 'sudo grep -q "^base pending" /var/lib/siem/install.state' && pass "Zustand: base pending" || fail "Zustand base fehlt"
vm '[ "$(sudo stat -c %a /var/lib/siem)" = 700 ]' && pass "Zustandsverzeichnis 0700" || fail "Rechte Zustandsverzeichnis"
vm '[ "$(sudo stat -c %a /var/lib/siem/answers.env)" = 600 ]' && pass "answers.env 0600" || fail "Rechte answers.env"
vm '[ "$(sudo stat -c %a /var/lib/siem/secrets)" = 700 ]' && pass "secrets/ 0700" || fail "Rechte secrets/"
vm 'sudo grep -q "siem.test.local" /var/lib/siem/answers.env && ! sudo grep -rq "Kennwort-fuer" /var/lib/siem/answers.env' \
    && pass "Antworten gespeichert, ohne Kennwörter" || fail "answers.env Inhalt"
vm '[ "$(sudo cat /var/lib/siem/secrets/web_admin_password)" = "Kennwort-fuer-webadmin-1" ]' \
    && pass "Geheimnis korrekt abgelegt" || fail "Geheimnis falsch"

# --- Test 6 ------------------------------------------------------------------
log "Test 6: --resume"
set +e
OUT=$(vm "sudo env NO_COLOR=1 ${LOW[*]} bash ~/siem/host/install.sh --resume" 2>&1 </dev/null)
RC=$?
set -e
printf '%s\n' "$OUT"
# Die Zustimmung zu Warnungen wurde gespeichert → Resume läuft ohne Rückfrage
[[ $RC -eq 3 ]] && pass "Exit 3" || fail "Resume: Exit 3 erwartet, erhalten $RC"
expect "Schritt base bereits erledigt|Schritt 'base' ist noch nicht implementiert" "Resume setzt beim offenen Schritt fort"
if grep -q 'Installationsfragen' <<<"$OUT"; then fail "Resume stellt Fragen erneut"; else pass "keine erneuten Fragen"; fi

log "Ergebnis"
if (( FAILED )); then echo "VM-Tests FEHLGESCHLAGEN"; exit 1; fi
echo "Alle VM-Tests bestanden."
