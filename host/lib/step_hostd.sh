# shellcheck shell=bash
# Schritt "hostd": privilegierten Host-Dienst siem-hostd einrichten (ADR-0009).
#   - Gruppe siem-hostd (Zugriff auf den Socket; später für den API-Container)
#   - Befehl /usr/local/sbin/siem-hostd
#   - systemd-Dienst siem-hostd.service (Socket /run/siem/hostd.sock)

readonly HOSTD_GROUP=siem-hostd
readonly HOSTD_UNIT=/etc/systemd/system/siem-hostd.service
readonly HOSTD_CLI=/usr/local/sbin/siem-hostd

step_hostd() {
    local rc1 rc2 i
    _base_install_host || return 1
    getent group "$HOSTD_GROUP" >/dev/null || run_cmd "Gruppe $HOSTD_GROUP" groupadd --system "$HOSTD_GROUP" || return 1
    install -d -m 0700 "$SIEM_ROOT/data/hostd" || return 1

    write_file "$HOSTD_CLI" 0755 <<EOF
#!/bin/sh
# Von install.sh verwaltet – Kommandozeile von siem-hostd
exec /usr/bin/python3 -I $SIEM_ROOT/host/siem-hostd/hostd.py "\$@"
EOF
    rc1=$?; (( rc1 <= 1 )) || return 1

    write_file "$HOSTD_UNIT" 0644 <<EOF
# Von install.sh verwaltet
[Unit]
Description=KMU-SIEM Host-Dienst (privilegierte Schnittstelle)
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
# Gruppe bestimmt den Eigentümer von /run/siem (Socket-Zugriff für Gruppenmitglieder)
Group=siem-hostd
ExecStart=/usr/bin/python3 -I $SIEM_ROOT/host/siem-hostd/hostd.py serve
Restart=always
RestartSec=2
RuntimeDirectory=siem
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
    rc2=$?; (( rc2 <= 1 )) || return 1

    if (( rc2 == 0 )); then
        run_cmd "systemd neu laden" systemctl daemon-reload || return 1
    fi
    run_cmd "siem-hostd aktivieren" systemctl enable siem-hostd.service || return 1
    if (( rc2 == 0 )) || ! systemctl is-active --quiet siem-hostd; then
        run_cmd "siem-hostd starten" systemctl restart siem-hostd.service || return 1
    fi

    for (( i = 0; i < 20; i++ )); do
        [[ -S /run/siem/hostd.sock ]] && break
        sleep 0.5
    done
    run_cmd "siem-hostd prüfen" "$HOSTD_CLI" system status || return 1
}
