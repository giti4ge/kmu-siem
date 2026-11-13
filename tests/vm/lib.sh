# shellcheck shell=bash
# shellcheck disable=SC2034,SC2016  # Variablen werden von den einbindenden Skripten genutzt
# Gemeinsame Hilfen der VM-Tests: frische Debian-13-VM (QEMU, Cloud-Image) starten,
# per SSH bedienen, Prüfungen protokollieren.
#
# Steuerung über Variablen vor dem Einbinden bzw. vor vm_boot:
#   VM_RAM_MB (4096), VM_CPUS (2), WORKDIR (./.vm), DEBIAN_IMAGE_URL
#   VM_DATA_DISK  yes|no (yes)  – zweite, leere 500-GB-Disk (/dev/vdb)
#   VM_ROOT_SIZE  Größe der System-Disk (40G)
#   VM_HOSTFWD    zusätzliche hostfwd-Regeln (Komma-getrennt, ohne SSH)

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORKDIR=${WORKDIR:-$REPO/.vm}
VM_RAM_MB=${VM_RAM_MB:-4096}
VM_CPUS=${VM_CPUS:-2}
VM_DATA_DISK=${VM_DATA_DISK:-yes}
VM_ROOT_SIZE=${VM_ROOT_SIZE:-40G}
VM_HOSTFWD=${VM_HOSTFWD:-}
DEBIAN_IMAGE_URL=${DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}
SSH_PORT=2222
FAILED=0
ADMIN_PW="Kennwort-fuer-siemadmin-1"
VM_USER=install
# Zugang per Kennwort statt Schlüssel (nur siemadmin ohne hinterlegten Schlüssel)
VM_USE_PASSWORD=no

log()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
pass() { printf '\033[32mOK\033[0m   %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }

# Niedrige Grenzwerte für die kleine Test-VM
LOW=(SIEM_MIN_CPU=1 SIEM_REC_CPU=1 SIEM_MIN_RAM_GB=2 SIEM_REC_RAM_GB=2)

vm_boot() {
    mkdir -p "$WORKDIR"
    cd "$WORKDIR" || exit 1
    log "Debian-13-Cloud-Image"
    [[ -f base.qcow2 ]] || curl -fsSL -o base.qcow2 "$DEBIAN_IMAGE_URL"
    rm -f system.qcow2 data.qcow2 seed.img id_ed25519 id_ed25519.pub serial.log
    qemu-img create -q -f qcow2 -F qcow2 -b base.qcow2 system.qcow2 "$VM_ROOT_SIZE"
    local disks=(-drive "file=system.qcow2,if=virtio")
    if [[ $VM_DATA_DISK == yes ]]; then
        qemu-img create -q -f qcow2 data.qcow2 500G          # leer, sparse
        disks+=(-drive "file=data.qcow2,if=virtio")
    fi
    ssh-keygen -q -t ed25519 -N '' -f id_ed25519 -C vm-test

    cat >user-data <<EOT
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
EOT
    printf 'instance-id: siem-vm-test\nlocal-hostname: siem\n' >meta-data
    cloud-localds seed.img user-data meta-data

    local accel=(-accel tcg) boot_timeout=900 t fwd
    if [[ -w /dev/kvm ]]; then accel=(-enable-kvm -cpu host); boot_timeout=300; else
        echo "WARNUNG: /dev/kvm nicht verfügbar – Software-Emulation (langsam)"; fi
    fwd="user,model=virtio,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22${VM_HOSTFWD:+,$VM_HOSTFWD}"

    log "VM starten (${VM_CPUS} vCPU, ${VM_RAM_MB} MB RAM, System ${VM_ROOT_SIZE}, Daten-Disk: ${VM_DATA_DISK})"
    qemu-system-x86_64 "${accel[@]}" -m "$VM_RAM_MB" -smp "$VM_CPUS" \
        "${disks[@]}" \
        -drive file=seed.img,if=virtio,format=raw \
        -nic "$fwd" \
        -display none -serial file:serial.log -daemonize -pidfile qemu.pid
    trap 'kill "$(cat "$WORKDIR/qemu.pid" 2>/dev/null)" 2>/dev/null || true' EXIT

    for (( t = 0; t < boot_timeout; t += 5 )); do
        vm true 2>/dev/null && break
        sleep 5
    done
    vm true || { tail -50 serial.log; echo "VM nicht erreichbar"; exit 1; }
    vm 'cloud-init status --wait >/dev/null 2>&1 || true'
    pass "VM erreichbar"

    # Repository-Teile übertragen
    tar -C "$REPO" -czf - host app VERSION | vm 'mkdir -p ~/siem && tar -C ~/siem -xzf -'
}

SSH_OPTS=(-p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30)
vm() {
    if [[ $VM_USE_PASSWORD == yes ]]; then
        SSHPASS=$ADMIN_PW sshpass -e ssh "${SSH_OPTS[@]}" -o PubkeyAuthentication=no \
            -o PreferredAuthentications=password "$VM_USER@127.0.0.1" "$@"
    else
        ssh -i "$WORKDIR/id_ed25519" "${SSH_OPTS[@]}" -o BatchMode=yes "$VM_USER@127.0.0.1" "$@"
    fi
}

# vmr SKRIPT – als root in der VM ausführen (nach der Installation: siemadmin + sudo-Kennwort)
vmr() {
    if [[ $VM_USER == install ]]; then
        vm "sudo bash -s" <<<"$1"
    else
        printf '%s\n%s\n' "$ADMIN_PW" "$1" | vm "sudo -S -p '' bash -s"
    fi
}
# check BESCHREIBUNG ROOT-SKRIPT
check() {
    local out
    if out=$(vmr "$2" 2>&1); then pass "$1"
    else fail "$1"; [[ -n $out ]] && printf '%s\n' "$out" | tail -15 | sed 's/^/       │ /'; fi
    return 0
}
expect() { if grep -qE -- "$1" <<<"$OUT"; then pass "$2"; else fail "$2 (Muster: $1)"; fi; }

# Ergebnis ausgeben und Exit-Code setzen; DIAG = Diagnose-Skript (root, in der VM)
finish() {
    log "Ergebnis"
    if (( FAILED )); then
        log "Diagnose"
        vmr "${1:-true}" 2>&1 || true
        echo "VM-Tests FEHLGESCHLAGEN"; exit 1
    fi
    echo "Alle VM-Tests bestanden."
}

# Gemeinsame Diagnose nach fehlgeschlagener Installation
DIAG='docker ps -a --format "{{.Names}} {{.Status}}"
echo "--- Ports"; ss -Hltnup | awk "{print \$1, \$5, \$7}"
echo "--- Vector"; docker logs --tail 60 siem-vector 2>&1
echo "--- OpenSearch"; docker logs --tail 40 siem-opensearch 2>&1 | cut -c1-300
echo "--- Zustand"; cat /var/lib/siem/install.state
echo "--- install.log"; tail -60 /var/log/siem-install.log'
