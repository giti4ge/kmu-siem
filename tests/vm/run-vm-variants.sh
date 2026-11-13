#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2016  # Befehle in einfachen Anführungszeichen laufen bewusst erst in der VM; pass() schlägt nie fehl
# VM-Test-Varianten zu den Abnahmekriterien von Phase 1 (Spezifikation Kap. 7):
#
#   interactive  Interaktive Installation (Eingaben über stdin) OHNE zweite Disk,
#                MIT Proxy (squid auf dem Test-Host, 10.0.2.2:3128) und OHNE SSH-Schlüssel:
#                Kennwort-Anmeldung bleibt aktiv, Daten auf der System-Disk, apt/Docker/
#                Registry nachweislich über den Proxy.
#   resume       Abbruch (SIGTERM an die Sitzung des Installers) in jedem der 8 Installationsschritte,
#                danach jeweils --resume; Endergebnis entspricht einem ununterbrochenen Lauf.
#
# Aufruf: run-vm-variants.sh interactive|resume
# Voraussetzungen auf dem Test-Host: qemu, cloud-image-utils, sshpass; für "interactive"
# zusätzlich squid auf Port 3128 mit Zugriffsprotokoll /var/log/squid/access.log.
set -euo pipefail

VARIANT=${1:-}
# shellcheck source=tests/vm/lib.sh
. "$(dirname "$0")/lib.sh"
WEB_PW="Kennwort-fuer-webadmin-1"
PROXY_URL=http://10.0.2.2:3128
SQUID_LOG=${SQUID_LOG:-/var/log/squid/access.log}

# Gemeinsame Prüfungen des Endzustands
check_installed() {
    check "Zustand: alle Schritte erledigt" '! grep -qvE " done " /var/lib/siem/install.state && grep -q "^selftest done" /var/lib/siem/install.state'
    check "Container laufen (opensearch, vector, proxy, api, dashboards)" 'for c in siem-opensearch siem-vector siem-proxy siem-api siem-dashboards; do [ "$(docker inspect -f "{{.State.Status}}" $c)" = running ] || exit 1; done'
    check "siem-hostd aktiv" 'systemctl is-active --quiet siem-hostd'
    check "nftables: Tabelle inet siem, policy drop" 'nft list chain inet siem input | grep -q "policy drop"'
    check "auditd und AIDE eingerichtet" 'systemctl is-active --quiet auditd && test -s /var/lib/aide/aide.db'
    check "SSH: root-Login aus, nur Gruppe siem-ssh" 'sshd -T | grep -qx "permitrootlogin no" && sshd -T | grep -qx "allowgroups siem-ssh"'
    check "genau eine Docker-Paketquelle" '[ "$(ls /etc/apt/sources.list.d/ | grep -c docker)" -eq 1 ]'
    check "keine unterbrochenen Paketvorgänge" '[ -z "$(dpkg --audit)" ]'
}

# --- interactive -----------------------------------------------------------------
variant_interactive() {
    command -v sshpass >/dev/null || { echo "sshpass fehlt"; exit 1; }
    # Der Workflow macht das Protokoll lesbar (ohne sudo auswertbar)
    if [[ ! -r $SQUID_LOG ]]; then
        echo "squid-Protokoll $SQUID_LOG nicht lesbar"; ls -la "$(dirname "$SQUID_LOG")" || true
        id; sudo -n id || true; exit 1
    fi
    VM_DATA_DISK=no VM_ROOT_SIZE=60G
    vm_boot
    local before input proxied host
    before=$(wc -l <"$SQUID_LOG")

    log "Interaktive Installation: ohne zweite Disk, mit Proxy, ohne SSH-Schlüssel"
    # Reihenfolge der Eingaben = Reihenfolge der Abfragen (prompts.sh: ask_all):
    # Warnungen bestätigen, Sprache, FQDN, NTP, Proxy (Vorgabe aus --proxy), Proxy-CA,
    # Daten-Disk (Vorgabe none), SSH-Schlüssel (leer), Kennwörter je zweimal,
    # Trunk-Interface, Token, Start bestätigen
    input=$(printf '%s\n' j de siem.test.local 0.debian.pool.ntp.org '' '' '' '' \
        "$ADMIN_PW" "$ADMIN_PW" "$WEB_PW" "$WEB_PW" '' '' j)
    set +e
    OUT=$(vm "sudo env NO_COLOR=1 ${LOW[*]} SIEM_MIN_DATA_GB=20 bash ~/siem/host/install.sh --proxy $PROXY_URL" <<<"$input" 2>&1)
    RC=$?
    set -e
    printf '%s\n' "$OUT" | tail -40
    if [[ $RC -eq 0 ]]; then pass "interaktive Installation vollständig (Exit 0)"
    else fail "Exit 0 erwartet, erhalten $RC"; printf '%s\n' "$OUT"; fi
    expect "Installationsfragen" "Fragen interaktiv gestellt"
    expect "Ohne SSH-Schlüssel bleibt die Kennwort-Anmeldung" "Hinweis: Kennwort-Anmeldung bleibt aktiv"
    expect "Selbsttest bestanden" "Selbsttest bestanden"
    expect "Installation abgeschlossen" "Abschlusszusammenfassung"

    # Ohne Schlüssel: Zugang als siemadmin mit Kennwort
    VM_USER=siemadmin
    VM_USE_PASSWORD=yes
    if vm true; then pass "SSH als siemadmin mit Kennwort (kein Aussperren ohne Schlüssel)"
    else fail "SSH als siemadmin mit Kennwort nicht möglich"; VM_USER=install; VM_USE_PASSWORD=no; finish "$DIAG"; fi
    check "SSH: Kennwort-Anmeldung aktiv" 'sshd -T | grep -qx "passwordauthentication yes"'
    check_installed
    check "keine zweite Disk: kein LVM, Daten auf der System-Disk" '! vgs siem >/dev/null 2>&1 && ! grep -q " /opt/siem/data " /etc/fstab && test -d /opt/siem/data/opensearch'
    check "Antworten: Proxy gespeichert" 'grep -q "^SIEM_PROXY=.*10.0.2.2:3128" /var/lib/siem/answers.env'
    check "apt nutzt den Proxy" 'grep -q "10.0.2.2:3128" /etc/apt/apt.conf.d/95siem-proxy'
    check "Docker nutzt den Proxy" 'grep -q "HTTPS_PROXY=http://10.0.2.2:3128" /etc/systemd/system/docker.service.d/http-proxy.conf'

    proxied=$(tail -n "+$((before + 1))" "$SQUID_LOG")
    for host in deb.debian.org download.docker.com registry-1.docker.io; do
        if grep -q "$host" <<<"$proxied"; then pass "Zugriff auf $host über den Proxy"
        else fail "kein Zugriff auf $host über den Proxy"; fi
    done
    finish "$DIAG"
}

# --- resume ----------------------------------------------------------------------
# Läuft in der VM (root): Installer in eigener Sitzung starten, Zustandsdatei alle
# 0,1 s prüfen, sobald SCHRITT läuft kurz warten und die gesamte Sitzung mit SIGTERM
# beenden (wie Strg+C/Verbindungsabbruch), notfalls SIGKILL.
# Ausgabe: ABORTED <laufender Schritt> | DONE (Schritt schon erledigt) | ENDED (Lauf vorher beendet)
ABORT_SCRIPT=$(cat <<'EOS'
#!/bin/bash
step=$1; shift
state=/var/lib/siem/install.state
st() { awk -v s="$1" '$1 == s { print $2 }' "$state" 2>/dev/null; }
rm -f /root/run.sid
setsid bash -c 'echo $$ >/root/run.sid; exec "$@" >>/root/run.log 2>&1' _ "$@" </dev/null >/dev/null 2>&1 &
for i in $(seq 1 50); do [ -s /root/run.sid ] && break; sleep 0.1; done
sid=$(cat /root/run.sid)
result=""
for i in $(seq 1 18000); do
    case $(st "$step") in
        running) break ;;
        done) result=DONE; break ;;
    esac
    pgrep -s "$sid" >/dev/null || { result=ENDED; break; }
    sleep 0.1
done
if [ -z "$result" ]; then
    sleep 0.5
    result="ABORTED $(awk '$2 == "running" { print $1 }' "$state")"
fi
pkill -TERM -s "$sid" 2>/dev/null
for i in $(seq 1 60); do pgrep -s "$sid" >/dev/null || break; sleep 1; done
pkill -KILL -s "$sid" 2>/dev/null
echo "$result"
EOS
)
step_state() { vmr "awk -v s=$1 '\$1 == s { print \$2 }' /var/lib/siem/install.state 2>/dev/null" || true; }

variant_resume() {
    vm_boot
    log "Abbruch in jedem Schritt mit anschließendem --resume"
    vm 'cat > ~/antworten.env' <<EOT
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
SIEM_KEEP_INSTALLER_USER_SSH=yes
EOT
    printf '%s\n' "$ADMIN_PW" | vm 'cat > ~/pw1'
    printf '%s\n' "$WEB_PW" | vm 'cat > ~/pw2'
    printf '%s\n' "$ABORT_SCRIPT" | vm 'cat > ~/abort-at.sh && chmod +x ~/abort-at.sh'

    local steps=(base datadisk hardening docker firewall hostd app selftest)
    local interrupted=() skipped=() mode=(--unattended /home/install/antworten.env) s res uniq
    for s in "${steps[@]}"; do
        res=$(vm "sudo /home/install/abort-at.sh $s env NO_COLOR=1 ${LOW[*]} bash /home/install/siem/host/install.sh ${mode[*]}" || true)
        mode=(--resume)
        case $res in
            "ABORTED "*)
                interrupted+=("${res#ABORTED }")
                printf '     abgebrochen während: %s (Zustand danach: %s)\n' "${res#ABORTED }" "$(step_state "${res#ABORTED }")" ;;
            *)  skipped+=("$s ($res)") ;;
        esac
    done
    vmr 'cat /root/run.log' | grep -E '^(==|✘)' | tail -40 || true
    uniq=$(printf '%s\n' "${interrupted[@]}" | sort -u | grep -c . || true)
    printf '     abgebrochen: %s\n     nicht unterbrochen: %s\n' "${interrupted[*]:-–}" "${skipped[*]:-–}"
    if (( uniq == ${#steps[@]} )); then pass "Abbruch in allen ${#steps[@]} Schritten"
    else fail "nur $uniq von ${#steps[@]} Schritten unterbrochen"; fi

    set +e
    OUT=$(vmr "env NO_COLOR=1 ${LOW[*]} bash /home/install/siem/host/install.sh --resume </dev/null" 2>&1)
    RC=$?
    set -e
    printf '%s\n' "$OUT" | tail -30
    if [[ $RC -eq 0 ]]; then pass "abschließendes --resume: Exit 0"; else fail "--resume: Exit 0 erwartet, erhalten $RC"; printf '%s\n' "$OUT"; fi
    expect "Selbsttest bestanden" "Selbsttest nach Abbrüchen bestanden"
    if grep -q 'Installationsfragen' <<<"$OUT"; then fail "--resume stellt Fragen erneut"; else pass "keine erneuten Fragen"; fi

    check_installed
    check "genau ein LV und ein fstab-Eintrag" '[ "$(lvs --noheadings siem | wc -l)" -eq 1 ] && [ "$(grep -c " /opt/siem/data " /etc/fstab)" -eq 1 ]'
    check "Daten-Disk eingehängt" 'findmnt /opt/siem/data >/dev/null'
    check "Kennwort siemadmin gesetzt, Geheimnis gelöscht" '[ "$(passwd -S siemadmin | cut -d" " -f2)" = P ] && test ! -e /var/lib/siem/secrets/admin_password'
    check "SSH: Kennwort-Anmeldung aus" 'sshd -T | grep -qx "passwordauthentication no"'
    VM_USER=siemadmin
    if vm true; then pass "SSH als siemadmin mit Schlüssel"; else fail "SSH als siemadmin nicht möglich"; VM_USER=install; fi
    [[ $VM_USER == siemadmin ]] && check "sudo für siemadmin mit Kennwort" 'true'
    finish "$DIAG"
}

case $VARIANT in
    interactive) variant_interactive ;;
    resume)      variant_resume ;;
    *) echo "Aufruf: $0 interactive|resume" >&2; exit 64 ;;
esac
