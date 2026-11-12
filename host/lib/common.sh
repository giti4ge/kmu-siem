# shellcheck shell=bash
# shellcheck disable=SC2034  # Exit-Codes/Farben werden in den übrigen Bibliotheken verwendet
# Gemeinsame Funktionen: Logging, Ausgabe, Fehlerbehandlung.
# Wird von install.sh eingebunden. Keine Seiteneffekte beim Einbinden.

# Pfade (für Tests überschreibbar)
: "${SIEM_LOG_FILE:=/var/log/siem-install.log}"
: "${SIEM_STATE_DIR:=/var/lib/siem}"
: "${SIEM_LANG:=de}"

# Exit-Codes (werden in den übrigen Bibliotheken verwendet)
readonly EX_OK=0
readonly EX_WARN=1
readonly EX_FAIL=2
readonly EX_NOT_IMPLEMENTED=3
readonly EX_USAGE=64

# Farben nur auf einem Terminal
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RED=$'\e[31m'; C_YEL=$'\e[33m'; C_GRN=$'\e[32m'; C_BLD=$'\e[1m'; C_RST=$'\e[0m'
else
    C_RED=''; C_YEL=''; C_GRN=''; C_BLD=''; C_RST=''
fi

# log LEVEL TEXT… – schreibt ins Installationsprotokoll (still, wenn nicht schreibbar)
log() {
    local level=$1; shift
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    { printf '%s [%s] %s\n' "$ts" "$level" "$*" >>"$SIEM_LOG_FILE"; } 2>/dev/null || true
}

info()  { printf '%s\n' "$*"; log INFO "$*"; }
ok()    { printf '%s✔%s %s\n' "$C_GRN" "$C_RST" "$*"; log OK "$*"; }
warn()  { printf '%s⚠%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; log WARN "$*"; }
err()   { printf '%s✘%s %s\n' "$C_RED" "$C_RST" "$*" >&2; log ERROR "$*"; }
die()   { local code=${2:-$EX_FAIL}; err "$1"; exit "$code"; }
heading() { printf '\n%s== %s ==%s\n' "$C_BLD" "$*" "$C_RST"; log INFO "== $* =="; }

# is_root – true, wenn mit Root-Rechten ausgeführt
is_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

# have CMD – true, wenn Befehl vorhanden
have() { command -v "$1" >/dev/null 2>&1; }

# trim TEXT – führende/folgende Leerzeichen entfernen
trim() {
    local s=$1
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# confirm FRAGE – Ja/Nein-Abfrage (Standard: Nein), liest von stdin.
confirm() {
    local answer
    printf '%s [%s] ' "$1" "$(msg yes_no_hint)"
    read -r answer || return 1
    case "${answer,,}" in
        j|ja|y|yes) return 0 ;;
        *) return 1 ;;
    esac
}
