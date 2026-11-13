# shellcheck shell=bash
# Antworten der Installation: Einlesen der Antwortdatei, Speichern/Laden.
#
# Sicherheit: Die Antwortdatei wird NICHT per `source` eingelesen, sondern Zeile
# für Zeile geparst. Werte werden nie ausgewertet (kein eval, keine Expansion).

# Erlaubte Schlüssel der Antwortdatei
readonly ANSWER_KEYS=(
    SIEM_LANG SIEM_FQDN SIEM_NTP SIEM_PROXY SIEM_PROXY_CA_FILE
    SIEM_DATA_DISK SIEM_DATA_DISK_CONFIRM
    SIEM_ADMIN_SSH_KEY SIEM_ADMIN_SSH_KEY_FILE
    SIEM_ADMIN_PASSWORD SIEM_ADMIN_PASSWORD_FILE
    SIEM_WEB_ADMIN_PASSWORD SIEM_WEB_ADMIN_PASSWORD_FILE
    SIEM_TRUNK_IF SIEM_TRUNK_VLANS
    SIEM_GITHUB_TOKEN_FILE
    SIEM_ACCEPT_WARNINGS SIEM_KEEP_INSTALLER_USER_SSH
)

# Pflichtangaben bei --unattended
readonly ANSWER_REQUIRED=(SIEM_FQDN SIEM_NTP SIEM_DATA_DISK)

# Nicht geheime Schlüssel, die im Zustandsverzeichnis gespeichert werden
readonly ANSWER_PERSIST=(
    SIEM_LANG SIEM_FQDN SIEM_NTP SIEM_PROXY SIEM_PROXY_CA_FILE
    SIEM_DATA_DISK SIEM_ADMIN_SSH_KEY SIEM_TRUNK_IF SIEM_TRUNK_VLANS
    SIEM_KEEP_INSTALLER_USER_SSH SIEM_ACCEPT_WARNINGS
)

declare -gA ANSWERS=()

_is_answer_key() {
    local k=$1 x
    for x in "${ANSWER_KEYS[@]}"; do [[ $x == "$k" ]] && return 0; done
    return 1
}

# parse_answer_file DATEI – füllt ANSWERS; Rückgabe 0 = OK, 2 = Fehler
parse_answer_file() {
    local file=$1 line key value n=0 rc=0
    [[ -f $file && -r $file ]] || { err "$(msg ans_file_missing "$file")"; return 2; }
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        line=${line%$'\r'}
        [[ $line =~ ^[[:space:]]*(#.*)?$ ]] && continue
        if [[ ! $line =~ ^[[:space:]]*([A-Z][A-Z0-9_]*)=(.*)$ ]]; then
            err "$(msg ans_bad_line "$n")"; rc=2; continue
        fi
        key=${BASH_REMATCH[1]}
        value=${BASH_REMATCH[2]}
        if ! _is_answer_key "$key"; then
            err "$(msg ans_unknown_key "$n" "$key")"; rc=2; continue
        fi
        value=$(_answer_value "$value")
        ANSWERS[$key]=$value
    done <"$file"
    return "$rc"
}

# _answer_value ROHWERT – Anführungszeichen entfernen, Kommentar am Zeilenende
# (nur bei unquotierten Werten, durch Leerzeichen getrennt) abschneiden.
_answer_value() {
    local v=$1
    v=$(trim "$v")
    if [[ $v =~ ^\"(.*)\"[[:space:]]*(#.*)?$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    elif [[ $v =~ ^\'(.*)\'[[:space:]]*(#.*)?$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        v=${v%%[[:space:]]#*}
        printf '%s' "$(trim "$v")"
    fi
}

# answer KEY [DEFAULT]
answer() { printf '%s' "${ANSWERS[$1]:-${2:-}}"; }

# read_secret_answer NAME – liefert Geheimnis aus NAME_FILE oder NAME (Klartext,
# mit Warnung). Rückgabe 1, wenn nicht gesetzt, 2 bei Fehler.
read_secret_answer() {
    local name=$1 file_key="${1}_FILE" file
    file=${ANSWERS[$file_key]:-}
    if [[ -n $file ]]; then
        [[ -f $file && -r $file ]] || { err "$(msg ans_file_unreadable "$file_key" "$file")"; return 2; }
        head -n1 -- "$file" | tr -d '\r\n'
        return 0
    fi
    if [[ -n ${ANSWERS[$name]:-} ]]; then
        warn "$(msg ans_plaintext_secret "$name")"
        printf '%s' "${ANSWERS[$name]}"
        return 0
    fi
    return 1
}

# check_required_answers – prüft Pflichtangaben für --unattended
check_required_answers() {
    local k rc=0
    for k in "${ANSWER_REQUIRED[@]}"; do
        [[ -n ${ANSWERS[$k]:-} ]] || { err "$(msg ans_missing_key "$k")"; rc=2; }
    done
    if [[ -n ${ANSWERS[SIEM_DATA_DISK]:-} && ${ANSWERS[SIEM_DATA_DISK]} != none \
          && ${ANSWERS[SIEM_DATA_DISK_CONFIRM]:-} != yes ]]; then
        err "$(msg ans_missing_key SIEM_DATA_DISK_CONFIRM=yes)"; rc=2
    fi
    return "$rc"
}

# save_answers – nicht geheime Antworten nach $SIEM_STATE_DIR/answers.env (0600)
save_answers() {
    local f="$SIEM_STATE_DIR/answers.env" tmp k
    install -d -m 0700 "$SIEM_STATE_DIR"
    tmp=$(mktemp "$SIEM_STATE_DIR/.answers.XXXXXX")
    chmod 0600 "$tmp"
    {
        printf '# Von install.sh erzeugt – nicht manuell bearbeiten\n'
        for k in "${ANSWER_PERSIST[@]}"; do
            [[ -n ${ANSWERS[$k]:-} ]] && printf '%s="%s"\n' "$k" "${ANSWERS[$k]//\"/}"
        done
    } >"$tmp"
    mv -f "$tmp" "$f"
}

# load_answers – gespeicherte Antworten laden (für --resume)
load_answers() {
    local f="$SIEM_STATE_DIR/answers.env"
    [[ -f $f ]] || return 1
    parse_answer_file "$f"
}

# save_secret NAME WERT – Geheimnis bis zum Verbrauch im Zustandsverzeichnis
# ablegen (0600). Wird vom verbrauchenden Schritt gelöscht.
save_secret() {
    local dir="$SIEM_STATE_DIR/secrets"
    install -d -m 0700 "$dir"
    ( umask 077; printf '%s' "$2" >"$dir/$1" )
}
