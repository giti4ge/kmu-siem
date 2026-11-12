# shellcheck shell=bash
# Schritt "base": Proxy/CA für apt, Systemaktualisierung, Abhängigkeiten,
# Host-Komponenten nach /opt/siem/host kopieren.

readonly BASE_PACKAGES=(
    ca-certificates curl gnupg jq openssl sudo
    nftables chrony auditd aide aide-common apparmor apparmor-utils
    lvm2 e2fsprogs unattended-upgrades apt-listchanges needrestart
    python3 lynis acl iproute2 util-linux
)

step_base() {
    _base_proxy || return
    run_cmd "Paketquellen aktualisieren" apt_get update || return
    run_cmd "System aktualisieren" apt_get full-upgrade || return
    apt_install "${BASE_PACKAGES[@]}" || return
    _base_install_host || return
}

# Proxy für apt und Proxy-CA im System-Zertifikatsspeicher
_base_proxy() {
    local f=/etc/apt/apt.conf.d/95siem-proxy rc
    if [[ -n ${SIEM_PROXY:-} ]]; then
        write_file "$f" 0644 <<EOF
// Von install.sh verwaltet
Acquire::http::Proxy "${SIEM_PROXY}";
Acquire::https::Proxy "${SIEM_PROXY}";
EOF
        rc=$?; (( rc <= 1 )) || return 1
    else
        rm -f "$f"
    fi
    if [[ -n ${SIEM_PROXY_CA_FILE:-} ]]; then
        install -m 0644 "$SIEM_PROXY_CA_FILE" /usr/local/share/ca-certificates/siem-proxy-ca.crt || return 1
        run_cmd "Proxy-CA übernehmen" update-ca-certificates || return 1
    fi
    return 0
}

# Installer-Dateien nach /opt/siem/host (für --repair, --preflight nach der Installation)
_base_install_host() {
    local src=$SIEM_HOST_DIR dst="$SIEM_ROOT/host" tmp
    [[ $(readlink -f "$src") == "$(readlink -f "$dst" 2>/dev/null)" ]] && return 0
    install -d -m 0755 "$SIEM_ROOT" || return 1
    tmp=$(mktemp -d "$SIEM_ROOT/.host.XXXXXX") || return 1
    cp -a "$src/." "$tmp/" || return 1
    chmod 0755 "$tmp"
    chown -R root:root "$tmp"
    rm -rf "$dst.old"
    [[ -d $dst ]] && mv "$dst" "$dst.old"
    mv "$tmp" "$dst" && rm -rf "$dst.old"
    [[ -f $SIEM_HOST_DIR/../VERSION ]] && install -m 0644 "$SIEM_HOST_DIR/../VERSION" "$SIEM_ROOT/VERSION"
    return 0
}
