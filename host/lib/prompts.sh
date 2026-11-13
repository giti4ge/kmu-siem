# shellcheck shell=bash
# shellcheck disable=SC2004  # ANSWERS ist ein assoziatives Array (answers.sh)
# Interaktive Abfragen und Übernahme aus der Antwortdatei.
# Ergebnis: ANSWERS[...] (nicht geheim) und Geheimnisse via save_secret.

# ask KEY TEXT DEFAULT VALIDATOR [optional]
# Fragt so lange, bis die Eingabe gültig ist. Leere Eingabe = DEFAULT.
# Ist "optional" gesetzt, ist eine leere Antwort (ohne Default) zulässig.
ask() {
    local key=$1 text=$2 def=$3 validator=$4 optional=${5:-} value
    while true; do
        if [[ -n $def ]]; then
            printf '%s [%s]: ' "$text" "$def"
        else
            printf '%s: ' "$text"
        fi
        IFS= read -r value || return 1
        value=$(trim "$value")
        [[ -z $value ]] && value=$def
        if [[ -z $value && -n $optional ]]; then
            ANSWERS[$key]=""
            return 0
        fi
        if [[ -n $value ]] && "$validator" "$value"; then
            ANSWERS[$key]=$value
            return 0
        fi
        warn "$(msg q_invalid "${value:-<leer>}")"
    done
}

# ask_secret NAME TEXT – Kennwort zweimal verdeckt abfragen
ask_secret() {
    local name=$1 text=$2 p1 p2
    while true; do
        printf '%s: ' "$text"; IFS= read -rs p1 || return 1; echo
        if ! valid_password "$p1"; then
            warn "$(msg q_invalid "≥ 12 Zeichen")"; continue
        fi
        printf '%s: ' "$(msg q_pw_repeat)"; IFS= read -rs p2 || return 1; echo
        if [[ $p1 != "$p2" ]]; then warn "$(msg q_pw_mismatch)"; continue; fi
        save_secret "$name" "$p1"
        return 0
    done
}

# Validatoren für optionale Werte bzw. Sonderfälle
_valid_datadisk() { [[ $1 == none ]] || valid_device "$1"; }
_valid_sshkey_input() {
    local v=$1
    if [[ -f $v ]]; then valid_ssh_pubkey "$(head -n1 -- "$v")"; else valid_ssh_pubkey "$v"; fi
}
_valid_trunk_if() { valid_iface "$1" && [[ $1 != "${PF_MGMT_IF:-}" ]]; }

# Verfügbare Netzwerkkarten (ohne lo und ohne Management-Karte)
_list_ifaces() {
    local d n out=()
    for d in "${SIEM_SYSROOT:-}"/sys/class/net/*; do
        n=${d##*/}
        [[ $n == lo || $n == "${PF_MGMT_IF:-}" || $n == docker* || $n == br-* || $n == veth* ]] && continue
        out+=("$n")
    done
    printf '%s' "${out[*]:-–}"
}

# ask_all – interaktive Fragen in festgelegter Reihenfolge
ask_all() {
    heading "$(msg q_title)"
    ask SIEM_LANG "$(msg q_lang)" "${SIEM_LANG}" valid_lang
    SIEM_LANG=${ANSWERS[SIEM_LANG]}
    ask SIEM_FQDN "$(msg q_fqdn)" "$(probe_fqdn)" valid_fqdn
    ask SIEM_NTP "$(msg q_ntp)" "$(_default_ntp)" valid_host_list
    ask SIEM_PROXY "$(msg q_proxy)" "${SIEM_PROXY:-}" valid_proxy_url optional
    if [[ -n ${ANSWERS[SIEM_PROXY]} ]]; then
        ask SIEM_PROXY_CA_FILE "$(msg q_proxy_ca)" "${SIEM_PROXY_CA_FILE:-}" valid_readable_file optional
    fi

    local disk_def=${PF_DATA_DISK:-none}
    ask SIEM_DATA_DISK "$(msg q_datadisk "$disk_def")" "$disk_def" _valid_datadisk
    if [[ ${ANSWERS[SIEM_DATA_DISK]} != none ]]; then
        local confirm_dev
        printf '%s: ' "$(msg q_datadisk_confirm "${ANSWERS[SIEM_DATA_DISK]}")"
        IFS= read -r confirm_dev || return 1
        [[ $(trim "$confirm_dev") == "${ANSWERS[SIEM_DATA_DISK]}" ]] || { err "$(msg q_aborted)"; return 1; }
        ANSWERS[SIEM_DATA_DISK_CONFIRM]=yes
    fi

    ask SIEM_ADMIN_SSH_KEY "$(msg q_sshkey)" "" _valid_sshkey_input optional
    if [[ -f ${ANSWERS[SIEM_ADMIN_SSH_KEY]} ]]; then
        ANSWERS[SIEM_ADMIN_SSH_KEY]=$(head -n1 -- "${ANSWERS[SIEM_ADMIN_SSH_KEY]}")
    fi
    [[ -n ${ANSWERS[SIEM_ADMIN_SSH_KEY]} ]] || warn "$(msg q_sshkey_none)"

    ask_secret admin_password "$(msg q_admin_pw)"
    ask_secret web_admin_password "$(msg q_web_pw)"

    ask SIEM_TRUNK_IF "$(msg q_trunk_if "$(_list_ifaces)")" "" _valid_trunk_if optional
    if [[ -n ${ANSWERS[SIEM_TRUNK_IF]} ]]; then
        ask SIEM_TRUNK_VLANS "$(msg q_trunk_vlans)" "" valid_vlan_list
    fi

    if [[ -z ${SIEM_GITHUB_TOKEN_FILE:-} ]]; then
        ask SIEM_GITHUB_TOKEN_FILE "$(msg q_token)" "" valid_readable_file optional
    else
        ANSWERS[SIEM_GITHUB_TOKEN_FILE]=$SIEM_GITHUB_TOKEN_FILE
    fi
    _store_token
}

# Standard-NTP: DNS-Server aus resolv.conf (in AD-Umgebungen meist die DCs)
_default_ntp() {
    awk '/^nameserver/ && $2 !~ /^127\./ { print $2 }' "${SIEM_SYSROOT:-}/etc/resolv.conf" 2>/dev/null \
        | paste -sd, -
}

# Token aus Datei übernehmen (als Geheimnis), Datei bleibt beim Benutzer
_store_token() {
    local f=${ANSWERS[SIEM_GITHUB_TOKEN_FILE]:-}
    [[ -n $f ]] || return 0
    save_secret github_token "$(head -n1 -- "$f" | tr -d '\r\n')"
}

# answers_from_file DATEI – unbeaufsichtigter Modus
answers_from_file() {
    local file=$1 secret rc
    parse_answer_file "$file" || return "$EX_FAIL"
    check_required_answers || return "$EX_FAIL"
    [[ -n ${ANSWERS[SIEM_LANG]:-} ]] && SIEM_LANG=${ANSWERS[SIEM_LANG]}

    local bad=0
    _check() { "$2" "$3" || { err "$(msg q_invalid "$1=$3")"; bad=1; }; }
    _check SIEM_LANG valid_lang "${ANSWERS[SIEM_LANG]:-$SIEM_LANG}"
    _check SIEM_FQDN valid_fqdn "${ANSWERS[SIEM_FQDN]}"
    _check SIEM_NTP valid_host_list "${ANSWERS[SIEM_NTP]}"
    _check SIEM_DATA_DISK _valid_datadisk "${ANSWERS[SIEM_DATA_DISK]}"
    [[ -n ${ANSWERS[SIEM_PROXY]:-} ]] && _check SIEM_PROXY valid_proxy_url "${ANSWERS[SIEM_PROXY]}"
    [[ -n ${ANSWERS[SIEM_PROXY_CA_FILE]:-} ]] && _check SIEM_PROXY_CA_FILE valid_readable_file "${ANSWERS[SIEM_PROXY_CA_FILE]}"
    [[ -n ${ANSWERS[SIEM_TRUNK_IF]:-} ]] && _check SIEM_TRUNK_IF _valid_trunk_if "${ANSWERS[SIEM_TRUNK_IF]}"
    if [[ -n ${ANSWERS[SIEM_TRUNK_IF]:-} ]]; then
        _check SIEM_TRUNK_VLANS valid_vlan_list "${ANSWERS[SIEM_TRUNK_VLANS]:-}"
    fi
    [[ -n ${ANSWERS[SIEM_GITHUB_TOKEN_FILE]:-} ]] && _check SIEM_GITHUB_TOKEN_FILE valid_readable_file "${ANSWERS[SIEM_GITHUB_TOKEN_FILE]}"

    # SSH-Schlüssel: direkt oder aus Datei
    if [[ -n ${ANSWERS[SIEM_ADMIN_SSH_KEY_FILE]:-} ]]; then
        if valid_readable_file "${ANSWERS[SIEM_ADMIN_SSH_KEY_FILE]}"; then
            ANSWERS[SIEM_ADMIN_SSH_KEY]=$(head -n1 -- "${ANSWERS[SIEM_ADMIN_SSH_KEY_FILE]}")
        else
            err "$(msg ans_file_unreadable SIEM_ADMIN_SSH_KEY_FILE "${ANSWERS[SIEM_ADMIN_SSH_KEY_FILE]}")"; bad=1
        fi
    fi
    if [[ -n ${ANSWERS[SIEM_ADMIN_SSH_KEY]:-} ]]; then
        _check SIEM_ADMIN_SSH_KEY valid_ssh_pubkey "${ANSWERS[SIEM_ADMIN_SSH_KEY]}"
    else
        warn "$(msg q_sshkey_none)"
    fi

    # Kennwörter (Pflicht)
    local name
    for name in SIEM_ADMIN_PASSWORD SIEM_WEB_ADMIN_PASSWORD; do
        secret=$(read_secret_answer "$name"); rc=$?
        if (( rc != 0 )); then
            (( rc == 1 )) && err "$(msg ans_missing_key "${name}_FILE")"
            bad=1; continue
        fi
        if ! valid_password "$secret"; then
            err "$(msg q_invalid "$name (≥ 12 Zeichen)")"; bad=1; continue
        fi
        if [[ $name == SIEM_ADMIN_PASSWORD ]]; then save_secret admin_password "$secret"
        else save_secret web_admin_password "$secret"; fi
    done
    unset -f _check
    (( bad == 0 )) || return "$EX_FAIL"
    _store_token
}

# print_summary – Zusammenfassung ohne Geheimnisse
print_summary() {
    heading "$(msg q_summary)"
    local k
    for k in SIEM_LANG SIEM_FQDN SIEM_NTP SIEM_PROXY SIEM_PROXY_CA_FILE SIEM_DATA_DISK \
             SIEM_TRUNK_IF SIEM_TRUNK_VLANS; do
        printf '  %-24s %s\n' "$k" "${ANSWERS[$k]:-–}"
    done
    local key=${ANSWERS[SIEM_ADMIN_SSH_KEY]:-}
    printf '  %-24s %s\n' SIEM_ADMIN_SSH_KEY "${key:+${key:0:24}…}"
    printf '  %-24s %s\n' SIEM_GITHUB_TOKEN "$([[ -n ${ANSWERS[SIEM_GITHUB_TOKEN_FILE]:-} ]] && echo '••••' || echo –)"
}
