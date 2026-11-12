# shellcheck shell=bash
# Installationszustand: welche Schritte sind erledigt (für --resume/--repair).
#
# Format von $SIEM_STATE_DIR/install.state (eine Zeile je Schritt):
#   <schritt> <status> <zeitstempel-utc> [<version>]
# Status: done | failed | running

state_file() { printf '%s/install.state' "$SIEM_STATE_DIR"; }

# state_get SCHRITT – gibt Status aus (leer, wenn unbekannt)
state_get() {
    local f
    f=$(state_file)
    [[ -f $f ]] || return 0
    awk -v s="$1" '$1 == s { st = $2 } END { if (st != "") print st }' "$f"
}

state_is_done() { [[ $(state_get "$1") == "done" ]]; }

# state_set SCHRITT STATUS – atomar schreiben
state_set() {
    local step=$1 status=$2 f tmp ts
    f=$(state_file)
    install -d -m 0700 "$SIEM_STATE_DIR"
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    tmp=$(mktemp "$SIEM_STATE_DIR/.state.XXXXXX")
    if [[ -f $f ]]; then
        awk -v s="$step" '$1 != s' "$f" >"$tmp"
    fi
    printf '%s %s %s %s\n' "$step" "$status" "$ts" "${SIEM_VERSION:-unknown}" >>"$tmp"
    chmod 0600 "$tmp"
    mv -f "$tmp" "$f"
    log STATE "$step=$status"
}

# state_exists – true, wenn eine Installation begonnen wurde
state_exists() { [[ -s $(state_file) ]]; }

# state_install_complete – true, wenn der letzte Schritt erledigt ist
state_install_complete() { state_is_done selftest; }
