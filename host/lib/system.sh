# shellcheck shell=bash
# Hilfsfunktionen für idempotente Systemänderungen (von den Installationsschritten genutzt).

: "${SIEM_ROOT:=/opt/siem}"

# run_cmd BESCHREIBUNG BEFEHL… – führt aus, protokolliert Ausgabe; zeigt bei Fehler das Ende
run_cmd() {
    local desc=$1; shift
    local out rc
    log CMD "$desc: $*"
    out=$("$@" 2>&1); rc=$?
    { printf '%s\n' "$out" >>"$SIEM_LOG_FILE"; } 2>/dev/null || true
    if (( rc != 0 )); then
        err "$desc (Exit $rc)"
        printf '%s\n' "$out" | tail -n 15 >&2
    fi
    return "$rc"
}

# write_file PFAD MODUS [BESITZER] – Inhalt von stdin; schreibt atomar nur bei Änderung.
# Rückgabe: 0 = geändert, 1 = unverändert, 2 = Fehler
write_file() {
    local path=$1 mode=$2 owner=${3:-root:root} tmp dir
    dir=$(dirname -- "$path")
    install -d -m 0755 "$dir" || return 2
    tmp=$(mktemp "$dir/.siem-new.XXXXXX") || return 2
    cat >"$tmp" || { rm -f "$tmp"; return 2; }
    if [[ -f $path ]] && cmp -s "$tmp" "$path" \
        && [[ $(stat -c %a "$path") == "${mode#0}" ]]; then
        rm -f "$tmp"
        return 1
    fi
    if ! { chmod "$mode" "$tmp" && chown "$owner" "$tmp" && mv -f "$tmp" "$path"; }; then
        rm -f "$tmp"; return 2
    fi
    log FILE "geschrieben: $path ($mode)"
    return 0
}

# changed RC – Hilfsfunktion: true, wenn write_file "geändert" meldete; bricht bei Fehler ab
changed() {
    case $1 in
        0) return 0 ;;
        1) return 1 ;;
        *) die "Datei konnte nicht geschrieben werden" ;;
    esac
}

# Umgebung für apt
apt_env() {
    export DEBIAN_FRONTEND=noninteractive
    export APT_LISTCHANGES_FRONTEND=none
    export NEEDRESTART_MODE=a
}

apt_get() {
    apt_env
    apt-get -q -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
}

# apt_install PAKET… – installiert nur fehlende Pakete
apt_install() {
    local missing=() p
    for p in "$@"; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing+=("$p")
    done
    (( ${#missing[@]} == 0 )) && return 0
    run_cmd "Pakete installieren: ${missing[*]}" apt_get install --no-install-recommends "${missing[@]}"
}

# curl mit Proxy-Einstellungen der Installation
siem_curl() {
    local args=(-fsSL --retry 3 --max-time 120)
    [[ -n ${SIEM_PROXY:-} ]] && args+=(--proxy "$SIEM_PROXY")
    curl "${args[@]}" "$@"
}

# svc_enable_now DIENST – aktivieren und starten (idempotent)
svc_enable_now() {
    run_cmd "Dienst $1 aktivieren" systemctl enable --now "$1"
}

# ssh_client_ips – Quell-IPs aller aktuell verbundenen SSH-Sitzungen
ssh_client_ips() {
    ss -Htn state established '( sport = :22 )' 2>/dev/null \
        | awk '{ addr = $4; sub(/:[0-9]+$/, "", addr); gsub(/^\[|\]$/, "", addr); sub(/^::ffff:/, "", addr); print addr }' \
        | sort -u
}
