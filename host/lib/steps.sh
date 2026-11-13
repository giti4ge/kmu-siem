# shellcheck shell=bash
# Installationsschritte in fester Reihenfolge.
# Jeder Schritt ist idempotent und wird nach Erfolg im Zustand als "done" vermerkt.
#
# Schritte ohne Funktion step_<name> enden mit EX_NOT_IMPLEMENTED (noch nicht
# implementiert). Implementierungen liegen in lib/step_<name>.sh.

# "name|Beschreibung|geplante Phase"
STEPS=(
    "base|Basis: Paketquellen, Systemaktualisierung, Abhängigkeiten|Phase 1.1"
    "datadisk|Daten-Disk: LVM, Dateisystem, Einhängen|Phase 1.1"
    "hardening|Härtung: Kernel, Module, SSH, auditd, AppArmor, Zeit, Updates|Phase 1.1"
    "docker|Docker Engine|Phase 1.1"
    "firewall|Firewall (nftables)|Phase 1.1"
    "hostd|Host-Dienste (siem-hostd)|Phase 1.2"
    "app|Anwendung: Images, Zertifikate, Start, Initialisierung|Phase 1.3"
    "selftest|Abschluss-Selbsttest (Ende-zu-Ende, AIDE, Lynis)|Phase 1.3"
)

step_name()  { local s=${STEPS[$1]}; printf '%s' "${s%%|*}"; }
step_desc()  { local s=${STEPS[$1]#*|}; printf '%s' "${s%%|*}"; }
step_phase() { local s=${STEPS[$1]}; printf '%s' "${s##*|}"; }

# Platzhalter für noch nicht implementierte Schritte
step_not_implemented() {
    local name=$1 phase=$2
    warn "$(msg step_not_impl "$name" "$phase")"
    return "$EX_NOT_IMPLEMENTED"
}

# run_steps – führt alle offenen Schritte aus
run_steps() {
    local i total=${#STEPS[@]} name rc fn
    # Nach der Basis-Installation immer die aktuelle Installer-Version nach /opt/siem/host
    if state_is_done base && declare -F _base_install_host >/dev/null; then
        _base_install_host || return 1
    fi
    for (( i = 0; i < total; i++ )); do
        name=$(step_name "$i")
        if state_is_done "$name"; then
            info "$(msg step_skip "$name")"
            continue
        fi
        heading "$(msg step_running $((i + 1)) "$total" "$(step_desc "$i")")"
        fn="step_$name"
        state_set "$name" running
        if declare -F "$fn" >/dev/null; then
            "$fn"; rc=$?
        else
            step_not_implemented "$name" "$(step_phase "$i")"; rc=$?
        fi
        if (( rc == 0 )); then
            state_set "$name" "done"
        elif (( rc == EX_NOT_IMPLEMENTED )); then
            state_set "$name" pending
            return "$rc"
        else
            state_set "$name" failed
            return "$rc"
        fi
    done
    return 0
}
