#!/usr/bin/env bash
# =============================================================================
# KMU-SIEM Appliance – Installationsskript
#
# Einziger Installationsweg der Appliance (SPEC 2.4.0, Abschnitt 4.1, ADR-20).
# Ausgangssituation: frische, schlanke Debian-13-VM mit SSH.
#
#   sudo ./install.sh                     interaktive Installation
#   sudo ./install.sh --preflight         nur Voraussetzungen prüfen
#   sudo ./install.sh --unattended DATEI  unbeaufsichtigt mit Antwortdatei
#   sudo ./install.sh --resume            abgebrochene Installation fortsetzen
#   sudo ./install.sh --repair            Sollzustand wiederherstellen
#
# Handbuch: docs/handbuch/03-installation.md
# =============================================================================
set -o nounset
set -o pipefail

SIEM_HOST_DIR=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)
SIEM_LIB_DIR="$SIEM_HOST_DIR/lib"
SIEM_VERSION=$(cat "$SIEM_HOST_DIR/../VERSION" 2>/dev/null || cat "$SIEM_HOST_DIR/VERSION" 2>/dev/null || echo unknown)
readonly SIEM_DEV_PHASE="Phase 1.2"

# shellcheck source=lib/common.sh
. "$SIEM_LIB_DIR/common.sh"
# shellcheck source=lib/i18n.sh
. "$SIEM_LIB_DIR/i18n.sh"
# shellcheck source=lib/validate.sh
. "$SIEM_LIB_DIR/validate.sh"
# shellcheck source=lib/state.sh
. "$SIEM_LIB_DIR/state.sh"
# shellcheck source=lib/answers.sh
. "$SIEM_LIB_DIR/answers.sh"
# shellcheck source=lib/preflight.sh
. "$SIEM_LIB_DIR/preflight.sh"
# shellcheck source=lib/prompts.sh
. "$SIEM_LIB_DIR/prompts.sh"
# shellcheck source=lib/steps.sh
. "$SIEM_LIB_DIR/steps.sh"
# shellcheck source=lib/system.sh
. "$SIEM_LIB_DIR/system.sh"
# shellcheck source=lib/step_base.sh
. "$SIEM_LIB_DIR/step_base.sh"
# shellcheck source=lib/step_datadisk.sh
. "$SIEM_LIB_DIR/step_datadisk.sh"
# shellcheck source=lib/step_hardening.sh
. "$SIEM_LIB_DIR/step_hardening.sh"
# shellcheck source=lib/step_docker.sh
. "$SIEM_LIB_DIR/step_docker.sh"
# shellcheck source=lib/step_firewall.sh
. "$SIEM_LIB_DIR/step_firewall.sh"
# shellcheck source=lib/step_hostd.sh
. "$SIEM_LIB_DIR/step_hostd.sh"

MODE=install
ANSWER_FILE=""
LOCK_FILE=/run/siem-install.lock

usage() { msg usage; echo; }

# set_mode NEUER_MODUS OPTION
set_mode() {
    if [[ $MODE != install && $MODE != "$1" ]]; then
        err "$(msg conflicting_modes "--$MODE" "$2")"; exit "$EX_USAGE"
    fi
    MODE=$1
}

parse_args() {
    while (( $# > 0 )); do
        case $1 in
            --preflight)  set_mode preflight "$1" ;;
            --resume)     set_mode resume "$1" ;;
            --repair)     set_mode repair "$1" ;;
            --unattended)
                [[ $# -ge 2 ]] || { err "$(msg missing_arg "$1")"; exit "$EX_USAGE"; }
                set_mode unattended "$1"; ANSWER_FILE=$2; shift ;;
            --proxy)
                [[ $# -ge 2 ]] || { err "$(msg missing_arg "$1")"; exit "$EX_USAGE"; }
                valid_proxy_url "$2" || { err "$(msg q_invalid "$2")"; exit "$EX_USAGE"; }
                SIEM_PROXY=$2; shift ;;
            --proxy-ca)
                [[ $# -ge 2 ]] || { err "$(msg missing_arg "$1")"; exit "$EX_USAGE"; }
                SIEM_PROXY_CA_FILE=$2; shift ;;
            --token-file)
                [[ $# -ge 2 ]] || { err "$(msg missing_arg "$1")"; exit "$EX_USAGE"; }
                SIEM_GITHUB_TOKEN_FILE=$2; shift ;;
            --keep-installer-user-ssh) ANSWERS[SIEM_KEEP_INSTALLER_USER_SSH]=yes ;;
            --lang)
                [[ $# -ge 2 ]] || { err "$(msg missing_arg "$1")"; exit "$EX_USAGE"; }
                valid_lang "$2" || { err "$(msg q_invalid "$2")"; exit "$EX_USAGE"; }
                SIEM_LANG=$2; shift ;;
            --version) printf 'kmu-siem installer %s\n' "$SIEM_VERSION"; exit "$EX_OK" ;;
            -h|--help) usage; exit "$EX_OK" ;;
            *) err "$(msg unknown_option "$1")"; usage >&2; exit "$EX_USAGE" ;;
        esac
        shift
    done
}

# Exklusive Sperre gegen parallele Läufe
acquire_lock() {
    exec 9>"$LOCK_FILE" || die "$(msg locked "$LOCK_FILE")"
    flock -n 9 || die "$(msg locked "$LOCK_FILE")"
}

# Preflight im Installationsablauf: Fehler → Abbruch, Warnungen → Rückfrage
preflight_gate() {
    local rc
    run_preflight; rc=$?
    (( rc == EX_FAIL )) && exit "$EX_FAIL"
    if (( rc == EX_WARN )); then
        # Zustimmung aus Antwortdatei bzw. gespeicherten Antworten (auch bei --resume)
        if [[ ${ANSWERS[SIEM_ACCEPT_WARNINGS]:-} == yes ]]; then
            :
        elif [[ $MODE == unattended ]]; then
            die "$(msg warn_continue) → SIEM_ACCEPT_WARNINGS=yes"
        else
            confirm "$(msg warn_continue)" || { info "$(msg q_aborted)"; exit "$EX_WARN"; }
            ANSWERS[SIEM_ACCEPT_WARNINGS]=yes
        fi
    fi
    # Management-Interface merken (für Trunk-Auswahl)
    PF_MGMT_IF=$(probe_ipv4 | awk 'NR == 1 { print $1 }')
}

main() {
    parse_args "$@"
    info "KMU-SIEM Installer $SIEM_VERSION"
    warn "$(msg dev_banner "$SIEM_DEV_PHASE")"

    case $MODE in
        preflight)
            # Nur prüfen – keine Sperre, kein Zustandsverzeichnis, keine Änderungen.
            # Gespeicherte Antworten (falls vorhanden) nur lesen, für die Anzeige.
            if state_exists; then load_answers >/dev/null 2>&1 || true; fi
            run_preflight
            exit $?
            ;;
        repair)
            is_root || die "$(msg need_root)"
            state_install_complete || die "$(msg repair_needs_install)"
            acquire_lock
            step_not_implemented repair "Phase 1"
            exit $?
            ;;
    esac

    is_root || die "$(msg need_root)"
    acquire_lock

    if [[ $MODE == unattended ]]; then
        parse_answer_file "$ANSWER_FILE" || exit "$EX_FAIL"
        [[ -n ${ANSWERS[SIEM_LANG]:-} ]] && SIEM_LANG=${ANSWERS[SIEM_LANG]}
        [[ -n ${ANSWERS[SIEM_PROXY]:-} ]] && SIEM_PROXY=${ANSWERS[SIEM_PROXY]}
        [[ -n ${ANSWERS[SIEM_PROXY_CA_FILE]:-} ]] && SIEM_PROXY_CA_FILE=${ANSWERS[SIEM_PROXY_CA_FILE]}
        SIEM_FQDN=${ANSWERS[SIEM_FQDN]:-}
    fi

    if [[ $MODE == resume ]]; then
        if state_exists && load_answers; then
            SIEM_LANG=${ANSWERS[SIEM_LANG]:-$SIEM_LANG}
            SIEM_PROXY=${ANSWERS[SIEM_PROXY]:-${SIEM_PROXY:-}}
            SIEM_FQDN=${ANSWERS[SIEM_FQDN]:-}
            preflight_gate
            run_steps
            exit $?
        fi
        info "$(msg resume_nothing)"
        MODE=install
    fi

    preflight_gate

    if [[ $MODE == unattended ]]; then
        answers_from_file "$ANSWER_FILE" || exit "$EX_FAIL"
    else
        ask_all || { info "$(msg q_aborted)"; exit "$EX_FAIL"; }
    fi

    print_summary
    if [[ $MODE != unattended ]]; then
        confirm "$(msg q_proceed)" || { info "$(msg q_aborted)"; exit "$EX_OK"; }
    fi

    save_answers
    state_set questions "done"
    run_steps
    exit $?
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
