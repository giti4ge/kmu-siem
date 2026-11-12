# shellcheck shell=bash
# Schritt "firewall": nftables-Grundkonfiguration der Appliance.
#
# Einzige Quelle der Regeln ist siem-hostd (Freigaben in /opt/siem/data/hostd/firewall.json,
# Erzeugung der nftables-Konfiguration in hostd.py). Der Installer ruft nur
# "firewall init" auf:
#   - legt beim ersten Lauf die Standard-Freigaben an,
#   - nimmt die Quell-IPs laufender SSH-Sitzungen in die SSH-Freigabe auf (kein Aussperren),
#   - schreibt /etc/nftables.conf und lädt die Regeln.
# Eigene Tabelle "inet siem" (kein "flush ruleset" – Dockers Tabellen bleiben erhalten).

readonly NFT_CONF=/etc/nftables.conf

step_firewall() {
    local args=() ip
    while read -r ip; do
        [[ -n $ip ]] && args+=(--add-ssh-source "$ip")
    done < <(ssh_client_ips)

    install -d -m 0700 "$SIEM_ROOT/data/hostd" || return 1
    [[ -f $NFT_CONF && ! -f $NFT_CONF.siem-backup ]] && cp -a "$NFT_CONF" "$NFT_CONF.siem-backup"
    run_cmd "Firewall-Freigaben anwenden" \
        /usr/bin/python3 -I "$SIEM_HOST_DIR/siem-hostd/hostd.py" firewall init "${args[@]}" || return 1
    _nft_service_dropin || return 1
    svc_enable_now nftables || return 1
}

# Debian: nftables.service führt beim Stoppen "nft flush ruleset" aus und würde damit
# auch Dockers Regeln löschen. Beim Stoppen wird nur die eigene Tabelle entfernt.
_nft_service_dropin() {
    local rc
    write_file /etc/systemd/system/nftables.service.d/siem.conf 0644 <<'EOF'
# Von install.sh verwaltet
[Service]
ExecStop=
ExecStop=-/usr/sbin/nft delete table inet siem
EOF
    rc=$?
    (( rc <= 1 )) || return 1
    (( rc == 0 )) && run_cmd "systemd neu laden" systemctl daemon-reload
    return 0
}
