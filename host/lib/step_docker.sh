# shellcheck shell=bash
# Schritt "docker": Docker Engine aus dem offiziellen Repository für Debian.

# Fingerabdruck des Docker-Release-Schlüssels (https://docs.docker.com/engine/install/debian/)
readonly DOCKER_GPG_FPR="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
readonly DOCKER_KEYRING=/etc/apt/keyrings/docker.asc
readonly DOCKER_PACKAGES=(docker-ce docker-ce-cli containerd.io docker-compose-plugin)

step_docker() {
    _docker_repo || return 1
    apt_install "${DOCKER_PACKAGES[@]}" || return 1
    _docker_daemon_config || return 1
    _docker_proxy || return 1
    svc_enable_now docker || return 1
    run_cmd "Docker prüfen" docker info --format '{{.ServerVersion}}' || return 1
    run_cmd "Docker Compose prüfen" docker compose version || return 1
}

_docker_repo() {
    local tmp fpr rc codename arch
    install -d -m 0755 /etc/apt/keyrings || return 1
    if [[ ! -s $DOCKER_KEYRING ]]; then
        tmp=$(mktemp) || return 1
        siem_curl -o "$tmp" https://download.docker.com/linux/debian/gpg || { err "Docker-Schlüssel nicht ladbar"; rm -f "$tmp"; return 1; }
        fpr=$(gpg --show-keys --with-colons "$tmp" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
        if [[ $fpr != "$DOCKER_GPG_FPR" ]]; then
            err "$(msg docker_key_mismatch "$fpr" "$DOCKER_GPG_FPR")"
            rm -f "$tmp"; return 1
        fi
        install -m 0644 "$tmp" "$DOCKER_KEYRING" && rm -f "$tmp"
    fi
    # shellcheck disable=SC1091
    codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-trixie}")
    arch=$(dpkg --print-architecture)
    write_file /etc/apt/sources.list.d/docker.sources 0644 <<EOF
# Von install.sh verwaltet
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: ${codename}
Components: stable
Architectures: ${arch}
Signed-By: ${DOCKER_KEYRING}
EOF
    rc=$?
    (( rc <= 1 )) || return 1
    if (( rc == 0 )) || ! apt-cache policy docker-ce 2>/dev/null | grep -q download.docker.com; then
        run_cmd "Paketquellen aktualisieren (Docker)" apt_get update || return 1
    fi
}

_docker_daemon_config() {
    local rc
    install -d -m 0755 /etc/docker || return 1
    # bridge=none: kein Standard-Bridge-Netz docker0; die Appliance nutzt ein eigenes Netz.
    write_file /etc/docker/daemon.json 0644 <<'EOF'
{
  "bridge": "none",
  "icc": false,
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "log-driver": "local",
  "log-opts": { "max-size": "20m", "max-file": "5" },
  "default-ulimits": { "nofile": { "Name": "nofile", "Soft": 65536, "Hard": 65536 } }
}
EOF
    rc=$?
    (( rc <= 1 )) || return 1
    if (( rc == 0 )) && systemctl is-active --quiet docker; then
        run_cmd "Docker neu starten" systemctl restart docker || return 1
    fi
}

# Proxy für den Docker-Daemon (Image-Downloads)
_docker_proxy() {
    local f=/etc/systemd/system/docker.service.d/http-proxy.conf rc
    if [[ -z ${SIEM_PROXY:-} ]]; then
        if [[ -f $f ]]; then
            rm -f "$f"
            run_cmd "systemd neu laden" systemctl daemon-reload || return 1
            systemctl is-active --quiet docker && run_cmd "Docker neu starten" systemctl restart docker
        fi
        return 0
    fi
    write_file "$f" 0644 <<EOF
# Von install.sh verwaltet
[Service]
Environment="HTTP_PROXY=${SIEM_PROXY}" "HTTPS_PROXY=${SIEM_PROXY}" "NO_PROXY=localhost,127.0.0.1,::1"
EOF
    rc=$?
    (( rc <= 1 )) || return 1
    if (( rc == 0 )); then
        run_cmd "systemd neu laden" systemctl daemon-reload || return 1
        systemctl is-active --quiet docker && run_cmd "Docker neu starten" systemctl restart docker
    fi
    return 0
}
