# shellcheck shell=bash
# Eingabevalidierung. Alle Funktionen geben 0 (gültig) oder 1 (ungültig) zurück
# und haben keine Seiteneffekte.

# valid_hostname NAME – einzelner DNS-Name (RFC 1123), auch FQDN
valid_hostname() {
    local h=$1
    [[ ${#h} -ge 1 && ${#h} -le 253 ]] || return 1
    [[ $h =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

# valid_fqdn NAME – mindestens zwei Labels, TLD nicht rein numerisch
valid_fqdn() {
    local h=$1
    valid_hostname "$h" || return 1
    [[ $h == *.* ]] || return 1
    [[ ! ${h##*.} =~ ^[0-9]+$ ]]
}

# valid_ipv4 ADRESSE
valid_ipv4() {
    local ip=$1 IFS=. octet
    [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    # shellcheck disable=SC2086
    set -- $ip
    for octet in "$@"; do
        [[ $octet =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
        (( octet <= 255 )) || return 1
    done
}

# valid_host_list "a,b,c" – kommagetrennte Hostnamen oder IPv4-Adressen
valid_host_list() {
    local list=$1 item
    [[ -n $list ]] || return 1
    IFS=, read -r -a items <<<"$list"
    for item in "${items[@]}"; do
        item=$(trim "$item")
        [[ -n $item ]] || return 1
        valid_ipv4 "$item" || valid_hostname "$item" || return 1
    done
}

# valid_proxy_url URL – http(s)://[benutzer:kennwort@]host[:port][/]
valid_proxy_url() {
    local u=$1 host port
    [[ $u =~ ^https?://([^/@[:space:]]+@)?([^/@:[:space:]]+)(:([0-9]{1,5}))?/?$ ]] || return 1
    host=${BASH_REMATCH[2]}
    port=${BASH_REMATCH[4]}
    valid_ipv4 "$host" || valid_hostname "$host" || return 1
    if [[ -n $port ]]; then (( 10#$port >= 1 && 10#$port <= 65535 )) || return 1; fi
    return 0
}

# valid_vlan_list "10,20,30-40" – IDs 1–4094, Bereiche aufsteigend
valid_vlan_list() {
    local list=$1 item a b
    [[ -n $list ]] || return 1
    IFS=, read -r -a items <<<"$list"
    for item in "${items[@]}"; do
        item=$(trim "$item")
        if [[ $item =~ ^([0-9]{1,4})-([0-9]{1,4})$ ]]; then
            a=$((10#${BASH_REMATCH[1]})); b=$((10#${BASH_REMATCH[2]}))
            (( a >= 1 && b <= 4094 && a < b )) || return 1
        elif [[ $item =~ ^[0-9]{1,4}$ ]]; then
            a=$((10#$item))
            (( a >= 1 && a <= 4094 )) || return 1
        else
            return 1
        fi
    done
}

# valid_ssh_pubkey "TYP SCHLÜSSEL [KOMMENTAR]" – Formatprüfung, bei Verfügbarkeit
# zusätzlich mit ssh-keygen
valid_ssh_pubkey() {
    local key=$1 tmp rc
    [[ $key =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\ [A-Za-z0-9+/]+={0,3}(\ .*)?$ ]] || return 1
    if command -v ssh-keygen >/dev/null 2>&1; then
        tmp=$(mktemp) || return 1
        printf '%s\n' "$key" >"$tmp"
        ssh-keygen -l -f "$tmp" >/dev/null 2>&1
        rc=$?
        rm -f "$tmp"
        return "$rc"
    fi
    return 0
}

# valid_password KENNWORT – mindestens 12 Zeichen, keine Steuerzeichen
valid_password() {
    local p=$1
    [[ ${#p} -ge 12 ]] || return 1
    [[ ! $p =~ [[:cntrl:]] ]]
}

# valid_lang de|en
valid_lang() { [[ $1 == de || $1 == en ]]; }

# valid_iface NAME – existierende Netzwerkkarte (nicht lo)
valid_iface() {
    local i=$1
    [[ $i =~ ^[A-Za-z0-9._-]{1,15}$ ]] || return 1
    [[ $i != lo ]] || return 1
    [[ -e "${SIEM_SYSROOT:-}/sys/class/net/$i" ]]
}

# valid_device PFAD – Blockgerät unter /dev
valid_device() {
    local d=$1
    [[ $d =~ ^/dev/[A-Za-z0-9/_-]+$ ]] || return 1
    [[ -b $d || -n ${SIEM_TEST_ALLOW_FAKE_DEVICES:-} ]]
}

# valid_readable_file PFAD
valid_readable_file() { [[ -f $1 && -r $1 ]]; }
