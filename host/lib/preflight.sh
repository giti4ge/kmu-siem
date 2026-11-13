# shellcheck shell=bash
# Preflight: prüft die Voraussetzungen, ändert NICHTS am System
# (einzige Ausnahme: Einträge im Installationsprotokoll).
#
# Aufbau:
#   probe_*  – lesen Systemzustand (in Tests ersetzbar)
#   pf_*     – bewerten und tragen Ergebnis ein
#   run_preflight – führt alle Prüfungen aus, gibt Tabelle aus
#                   Rückgabe: 0 = OK, 1 = Warnungen, 2 = Fehler

# --- Schwellwerte (per Umgebung überschreibbar, z. B. für Testumgebungen) ----
: "${SIEM_MIN_CPU:=4}"
: "${SIEM_REC_CPU:=6}"
: "${SIEM_MIN_RAM_GB:=16}"
: "${SIEM_REC_RAM_GB:=24}"
: "${SIEM_MIN_DATA_GB:=500}"
: "${SIEM_REC_ROOT_GB:=40}"
: "${SIEM_NET_TIMEOUT:=10}"

# Toleranz: Ein "16-GB"-System meldet etwas weniger (Kernel-Reservierung),
# eine "500-GB"-Disk im Hypervisor ist oft 500 GiB oder 500 GB. Grenzen werden
# deshalb mit 90 % (RAM) bzw. 93 % (Disk, ≈ GiB→GB) bewertet.
readonly PF_RAM_TOLERANCE=90
readonly PF_DISK_TOLERANCE=93

# Ziele für die Internet-Prüfung: "Name|URL"
PF_NET_TARGETS=(
    "Debian|https://deb.debian.org/debian/dists/trixie/Release"
    "Debian Security|https://security.debian.org/debian-security/dists/trixie-security/Release"
    "Docker|https://download.docker.com/linux/debian/dists/trixie/Release"
    "GitHub API|https://api.github.com/"
    "GitHub Container Registry|https://ghcr.io/v2/"
)

# Ports, die die Appliance benötigt: "port/proto"
PF_PORTS=(443/tcp 514/tcp 514/udp 6514/tcp 5985/tcp 5986/tcp 162/udp)

# Pakete, die auf eine Desktop-Umgebung hinweisen
PF_DESKTOP_PKGS=(task-desktop xserver-xorg-core gdm3 lightdm sddm gnome-shell plasma-desktop xfce4-session)

# Fremde Container-Laufzeiten
PF_CONTAINER_PKGS=(docker.io docker-ce podman containerd.io containerd)

# Ergebnis-Tabellen
PF_KEYS=(); PF_STATUS=(); PF_DETAIL=()
PF_FAILS=0; PF_WARNS=0

# Proxy (aus --proxy oder Antwort)
: "${SIEM_PROXY:=}"

# =============================================================================
# Probes – lesen nur
# =============================================================================
probe_os() {
    # Ausgabe: ID|VERSION_ID|PRETTY_NAME
    local f="${SIEM_SYSROOT:-}/etc/os-release"
    [[ -r $f ]] || { printf 'unknown||unknown'; return; }
    ( # shellcheck disable=SC1090
      . "$f"; printf '%s|%s|%s' "${ID:-unknown}" "${VERSION_ID:-}" "${PRETTY_NAME:-unknown}" )
}
probe_arch() { dpkg --print-architecture 2>/dev/null || uname -m; }
probe_is_root() { is_root; }
probe_systemd() { [[ -d "${SIEM_SYSROOT:-}/run/systemd/system" ]]; }
probe_cpu_count() { nproc 2>/dev/null || getconf _NPROCESSORS_ONLN; }
probe_mem_kb() { awk '/^MemTotal:/ { print $2 }' "${SIEM_SYSROOT:-}/proc/meminfo"; }
# Ausgabe: "<gesamt-KB> <frei-KB>" der Root-Partition
probe_rootfs_kb() { df -Pk / | awk 'NR == 2 { print $2, $4 }'; }

# Leere Disks: Ausgabe je Zeile "<gerät> <bytes>"
# Kriterien: TYPE=disk, beschreibbar, keine Partitionen/Kinder, keine Signatur,
# nicht die Disk der Root-Partition, nicht wechselbar.
probe_empty_disks() {
    have lsblk || return 0
    local rootdev rootdisk name type size ro rm children
    rootdev=$(findmnt -no SOURCE / 2>/dev/null || true)
    rootdisk=$(lsblk -no PKNAME "$rootdev" 2>/dev/null | head -n1 || true)
    while read -r name type size ro rm; do
        [[ $type == disk && $ro == 0 && $rm == 0 ]] || continue
        [[ -n $rootdisk && $name == "/dev/$rootdisk" ]] && continue
        children=$(lsblk -npo NAME "$name" 2>/dev/null | wc -l)
        (( children == 1 )) || continue
        if have wipefs; then
            [[ -z $(wipefs -n "$name" 2>/dev/null | tail -n +2) ]] || continue
        fi
        printf '%s %s\n' "$name" "$size"
    done < <(lsblk -dpnbo NAME,TYPE,SIZE,RO,RM 2>/dev/null)
}

# Globale IPv4-Adressen: Ausgabe je Zeile "<iface> <cidr> static|dynamic"
probe_ipv4() {
    have ip || return 0
    ip -4 -o addr show scope global 2>/dev/null | awk '{
        mode = "static"; for (i = 1; i <= NF; i++) if ($i == "dynamic") mode = "dynamic";
        print $2, $4, mode }'
}
probe_fqdn() { hostname -f 2>/dev/null || hostname; }
probe_resolve() { getent ahostsv4 "$1" 2>/dev/null | awk 'NR == 1 { print $1 }'; }
probe_time_synced() {
    have timedatectl || return 1
    [[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) == yes ]]
}

# probe_http URL – 0, wenn der Server antwortet (beliebiger HTTP-Status)
probe_http() {
    local url=$1 code rc
    if have curl; then
        local args=(-sS -o /dev/null --max-time "$SIEM_NET_TIMEOUT" -w '%{http_code}')
        [[ -n $SIEM_PROXY ]] && args+=(--proxy "$SIEM_PROXY")
        [[ -n ${SIEM_PROXY_CA_FILE:-} ]] && args+=(--cacert "$SIEM_PROXY_CA_FILE")
        code=$(curl "${args[@]}" "$url" 2>/dev/null) || true
        [[ -n $code && $code != 000 ]]
        return
    fi
    if have wget; then
        local args=(-q --spider -T "$SIEM_NET_TIMEOUT" -t 1)
        [[ -n ${SIEM_PROXY_CA_FILE:-} ]] && args+=(--ca-certificate="$SIEM_PROXY_CA_FILE")
        https_proxy=$SIEM_PROXY http_proxy=$SIEM_PROXY wget "${args[@]}" "$url" >/dev/null 2>&1
        rc=$?
        # 0 = OK, 8 = Server hat mit Fehlerstatus geantwortet (= erreichbar)
        [[ $rc -eq 0 || $rc -eq 8 ]]
        return
    fi
    return 2
}

# Belegte Ports: Ausgabe je Zeile "<port>/<proto>"
probe_listening() {
    have ss || return 0
    ss -H -lntu 2>/dev/null | awk '{ n = split($5, a, ":"); print a[n] "/" $1 }'
}

# Installierte Pakete aus Liste: Ausgabe der installierten Namen
probe_installed_pkgs() {
    local p
    have dpkg-query || return 0
    for p in "$@"; do
        if dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed'; then
            printf '%s\n' "$p"
        fi
    done
}

# =============================================================================
# Bewertung
# =============================================================================
pf_reset() { PF_KEYS=(); PF_STATUS=(); PF_DETAIL=(); PF_FAILS=0; PF_WARNS=0; }

# pf_add STATUS(ok|warn|fail|info) TITEL DETAIL
pf_add() {
    PF_STATUS+=("$1"); PF_KEYS+=("$2"); PF_DETAIL+=("$3")
    case $1 in
        fail) PF_FAILS=$((PF_FAILS + 1)) ;;
        warn) PF_WARNS=$((PF_WARNS + 1)) ;;
    esac
    log PREFLIGHT "$1 | $2 | $3"
}

# Hilfsfunktion: a >= b * pct / 100
_ge_pct() { (( $1 * 100 >= $2 * $3 )); }

pf_os() {
    local id ver pretty arch
    IFS='|' read -r id ver pretty <<<"$(probe_os)"
    arch=$(probe_arch)
    if [[ $id == debian && ${ver%%.*} == 13 && ( $arch == amd64 || $arch == x86_64 ) ]]; then
        pf_add ok "$(msg pf_os)" "$(msg pf_os_ok "$ver" "$arch")"
    else
        pf_add fail "$(msg pf_os)" "$(msg pf_os_bad "$pretty" "$arch")"
    fi
}

pf_root() {
    if probe_is_root; then pf_add ok "$(msg pf_root)" "root"
    else pf_add fail "$(msg pf_root)" "$(msg pf_root_bad)"; fi
}

pf_systemd() {
    if probe_systemd; then pf_add ok "$(msg pf_systemd)" "PID 1"
    else pf_add fail "$(msg pf_systemd)" "$(msg pf_systemd_bad)"; fi
}

pf_cpu() {
    local n
    n=$(probe_cpu_count)
    local detail
    detail=$(msg pf_cpu_val "$n" "$SIEM_MIN_CPU" "$SIEM_REC_CPU")
    if (( n < SIEM_MIN_CPU )); then pf_add fail "$(msg pf_cpu)" "$detail"
    elif (( n < SIEM_REC_CPU )); then pf_add warn "$(msg pf_cpu)" "$detail"
    else pf_add ok "$(msg pf_cpu)" "$detail"; fi
}

pf_ram() {
    local kb gb detail
    kb=$(probe_mem_kb)
    gb=$(( (kb + 524288) / 1048576 ))   # gerundet auf GiB
    detail=$(msg pf_ram_val "$gb" "$SIEM_MIN_RAM_GB" "$SIEM_REC_RAM_GB")
    if ! _ge_pct "$kb" $(( SIEM_MIN_RAM_GB * 1048576 )) "$PF_RAM_TOLERANCE"; then
        pf_add fail "$(msg pf_ram)" "$detail"
    elif ! _ge_pct "$kb" $(( SIEM_REC_RAM_GB * 1048576 )) "$PF_RAM_TOLERANCE"; then
        pf_add warn "$(msg pf_ram)" "$detail"
    else
        pf_add ok "$(msg pf_ram)" "$detail"
    fi
}

pf_rootfs() {
    local total free tgb fgb detail
    read -r total free <<<"$(probe_rootfs_kb)"
    tgb=$(( total / 1000000 )); fgb=$(( free / 1000000 ))
    detail=$(msg pf_rootfs_val "$tgb" "$fgb" "$SIEM_REC_ROOT_GB")
    if _ge_pct "$total" $(( SIEM_REC_ROOT_GB * 1000000 )) "$PF_DISK_TOLERANCE"; then
        pf_add ok "$(msg pf_rootfs)" "$detail"
    else
        pf_add warn "$(msg pf_rootfs)" "$detail"
    fi
    PF_ROOT_FREE_KB=$free
}

# Setzt PF_DATA_DISK (erste geeignete Disk oder leer)
pf_datadisk() {
    local name bytes gb best="" best_gb=0 small=""
    local min_bytes=$(( SIEM_MIN_DATA_GB * 1000000000 ))
    while read -r name bytes; do
        [[ -n $name ]] || continue
        gb=$(( bytes / 1000000000 ))
        if _ge_pct "$bytes" "$min_bytes" "$PF_DISK_TOLERANCE"; then
            if (( gb > best_gb )); then best=$name; best_gb=$gb; fi
        else
            small="$name|$gb"
        fi
    done < <(probe_empty_disks)

    # shellcheck disable=SC2034  # wird in prompts.sh verwendet
    PF_DATA_DISK=$best
    if [[ -n $best ]]; then
        pf_add ok "$(msg pf_datadisk)" "$(msg pf_datadisk_found "$best" "$best_gb")"
        return
    fi
    local free_gb=$(( ${PF_ROOT_FREE_KB:-0} / 1000000 ))
    if [[ -n $small ]]; then
        pf_add warn "$(msg pf_datadisk)" "$(msg pf_datadisk_small "${small%%|*}" "${small##*|}" "$SIEM_MIN_DATA_GB")"
    fi
    if _ge_pct "${PF_ROOT_FREE_KB:-0}" $(( SIEM_MIN_DATA_GB * 1000000 )) "$PF_DISK_TOLERANCE"; then
        pf_add warn "$(msg pf_datadisk)" "$(msg pf_datadisk_none_ok "$free_gb")"
    else
        pf_add fail "$(msg pf_datadisk)" "$(msg pf_datadisk_none_bad "$free_gb" "$SIEM_MIN_DATA_GB")"
    fi
}

pf_ip() {
    local iface cidr mode found=0
    while read -r iface cidr mode; do
        [[ -n $iface ]] || continue
        found=1
        if [[ $mode == dynamic ]]; then
            pf_add warn "$(msg pf_ip)" "$(msg pf_ip_dhcp "$iface $cidr")"
        else
            pf_add ok "$(msg pf_ip)" "$(msg pf_ip_static "$iface $cidr")"
        fi
    done < <(probe_ipv4)
    (( found )) || pf_add fail "$(msg pf_ip)" "$(msg pf_ip_none)"
}

pf_dns() {
    local fqdn=${SIEM_FQDN:-} addr
    [[ -n $fqdn ]] || fqdn=$(probe_fqdn)
    if [[ $fqdn != *.* ]]; then
        pf_add warn "$(msg pf_dns)" "$(msg pf_dns_noqual "$fqdn")"
        return
    fi
    addr=$(probe_resolve "$fqdn")
    if [[ -n $addr && $addr != 127.* ]]; then
        pf_add ok "$(msg pf_dns)" "$(msg pf_dns_ok "$fqdn" "$addr")"
    else
        pf_add warn "$(msg pf_dns)" "$(msg pf_dns_bad "$fqdn")"
    fi
}

pf_time() {
    if probe_time_synced; then pf_add ok "$(msg pf_time)" "$(msg pf_time_ok)"
    else pf_add warn "$(msg pf_time)" "$(msg pf_time_bad)"; fi
}

pf_net() {
    local entry name url via="" rc
    [[ -n $SIEM_PROXY ]] && via=$(msg pf_net_via_proxy)
    for entry in "${PF_NET_TARGETS[@]}"; do
        name=${entry%%|*}; url=${entry#*|}
        probe_http "$url"; rc=$?
        if (( rc == 2 )); then
            pf_add fail "$(msg pf_net "$name")" "$(msg pf_net_tool_missing)"
            return
        elif (( rc == 0 )); then
            pf_add ok "$(msg pf_net "$name")" "$(msg pf_net_ok "$via")"
        else
            pf_add fail "$(msg pf_net "$name")" "$(msg pf_net_bad "$via")"
        fi
    done
}

pf_ports() {
    local used=() p listening
    listening=$(probe_listening)
    for p in "${PF_PORTS[@]}"; do
        grep -qxF "$p" <<<"$listening" && used+=("$p")
    done
    if (( ${#used[@]} == 0 )); then
        pf_add ok "$(msg pf_ports)" "$(msg pf_ports_ok)"
    elif state_is_done app; then
        pf_add info "$(msg pf_ports)" "$(msg pf_ports_siem)"
    else
        pf_add fail "$(msg pf_ports)" "$(msg pf_ports_bad "${used[*]}")"
    fi
}

pf_container() {
    local found
    found=$(probe_installed_pkgs "${PF_CONTAINER_PKGS[@]}" | paste -sd' ' -)
    if [[ -z $found ]]; then
        pf_add ok "$(msg pf_docker)" "$(msg pf_docker_ok)"
    elif state_is_done docker; then
        pf_add info "$(msg pf_docker)" "$(msg pf_docker_siem)"
    else
        pf_add fail "$(msg pf_docker)" "$(msg pf_docker_bad "$found")"
    fi
}

pf_desktop() {
    local found
    found=$(probe_installed_pkgs "${PF_DESKTOP_PKGS[@]}" | paste -sd' ' -)
    if [[ -z $found ]]; then pf_add ok "$(msg pf_desktop)" "$(msg pf_desktop_ok)"
    else pf_add fail "$(msg pf_desktop)" "$(msg pf_desktop_bad "$found")"; fi
}

pf_existing() {
    if ! state_exists; then
        pf_add info "$(msg pf_existing)" "$(msg pf_existing_none)"
    elif state_install_complete; then
        pf_add info "$(msg pf_existing)" "$(msg pf_existing_done)"
    else
        pf_add info "$(msg pf_existing)" "$(msg pf_existing_partial)"
    fi
}

# Überschriebene Schwellwerte melden
pf_overrides() {
    local v changed=()
    for v in SIEM_MIN_CPU SIEM_MIN_RAM_GB SIEM_MIN_DATA_GB; do
        case $v in
            SIEM_MIN_CPU)     [[ $SIEM_MIN_CPU != 4 ]]       && changed+=("$v=$SIEM_MIN_CPU") ;;
            SIEM_MIN_RAM_GB)  [[ $SIEM_MIN_RAM_GB != 16 ]]   && changed+=("$v=$SIEM_MIN_RAM_GB") ;;
            SIEM_MIN_DATA_GB) [[ $SIEM_MIN_DATA_GB != 500 ]] && changed+=("$v=$SIEM_MIN_DATA_GB") ;;
        esac
    done
    (( ${#changed[@]} == 0 )) || warn "$(msg pf_threshold_override "${changed[*]}")"
}

# Tabelle ausgeben
pf_print() {
    local i sym color
    for i in "${!PF_KEYS[@]}"; do
        case ${PF_STATUS[$i]} in
            ok)   sym='✔'; color=$C_GRN ;;
            warn) sym='⚠'; color=$C_YEL ;;
            fail) sym='✘'; color=$C_RED ;;
            *)    sym='ℹ'; color='' ;;
        esac
        printf '  %s%s%s %-28s %s\n' "$color" "$sym" "$C_RST" "${PF_KEYS[$i]}" "${PF_DETAIL[$i]}"
    done
}

# run_preflight – alle Prüfungen
run_preflight() {
    pf_reset
    heading "$(msg pf_title)"
    pf_overrides
    pf_os
    pf_root
    pf_systemd
    pf_cpu
    pf_ram
    pf_rootfs
    pf_datadisk
    pf_ip
    pf_dns
    pf_time
    pf_net
    pf_ports
    pf_container
    pf_desktop
    pf_existing
    pf_print
    echo
    if (( PF_FAILS > 0 )); then
        err "$(msg pf_summary_fail "$PF_FAILS" "$PF_WARNS")"
        return "$EX_FAIL"
    elif (( PF_WARNS > 0 )); then
        warn "$(msg pf_summary_warn "$PF_WARNS")"
        return "$EX_WARN"
    fi
    ok "$(msg pf_summary_ok)"
    return "$EX_OK"
}
