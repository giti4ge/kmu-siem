# shellcheck shell=bash
# Schritt "firewall": nftables-Grundkonfiguration der Appliance.
#
# - Eigene Tabelle "inet siem" (KEIN "flush ruleset" – Dockers Tabellen bleiben erhalten)
# - input: drop; erlaubt sind nur freigegebene Dienste aus den jeweiligen Quell-Sets
# - forward: drop; erlaubt ist nur ausgehender Verkehr der Appliance-Bridge (br-siem)
# - Quell-IPs laufender SSH-Sitzungen werden immer in allow_ssh aufgenommen (kein Aussperren)
# Die Sets werden später über siem-hostd (Web-UI, Dead-Man's-Switch) gepflegt.

readonly NFT_CONF=/etc/nftables.conf
readonly SIEM_BRIDGE=br-siem
readonly NFT_DEFAULT_V4="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
readonly NFT_DEFAULT_V6="fc00::/7, fe80::/10"

step_firewall() {
    local ssh4="" ssh6="" ip rc
    while read -r ip; do
        [[ -z $ip ]] && continue
        if [[ $ip == *:* ]]; then ssh6+="${ssh6:+, }$ip"; else ssh4+="${ssh4:+, }$ip"; fi
    done < <(ssh_client_ips)

    nft_render "$ssh4" "$ssh6" | write_file "$NFT_CONF.siem-new" 0600
    rc=$?; (( rc <= 1 )) || return 1
    if ! run_cmd "Firewall-Regeln prüfen" nft -c -f "$NFT_CONF.siem-new"; then
        rm -f "$NFT_CONF.siem-new"; return 1
    fi
    if cmp -s "$NFT_CONF.siem-new" "$NFT_CONF" 2>/dev/null; then
        rm -f "$NFT_CONF.siem-new"
    else
        [[ -f $NFT_CONF ]] && cp -a "$NFT_CONF" "$NFT_CONF.siem-backup"
        mv -f "$NFT_CONF.siem-new" "$NFT_CONF"
        chmod 0600 "$NFT_CONF"
    fi
    _nft_service_dropin || return 1
    run_cmd "Firewall laden" nft -f "$NFT_CONF" || return 1
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

# nft_render SSH_IPV4 SSH_IPV6 – gibt die vollständige Konfiguration aus
nft_render() {
    local ssh4=$1 ssh6=$2
    local ssh4_elems="$NFT_DEFAULT_V4${ssh4:+, $ssh4}"
    local ssh6_elems="$NFT_DEFAULT_V6${ssh6:+, $ssh6}"
    cat <<EOF
#!/usr/sbin/nft -f
# Von install.sh / siem-hostd verwaltet – KMU-SIEM Appliance-Firewall
# Nur die Tabelle "inet siem" wird ersetzt; Tabellen von Docker bleiben unberührt.

table inet siem
delete table inet siem

table inet siem {
    # Quell-Freigaben je Dienst (IPv4)
    set allow_ssh        { type ipv4_addr; flags interval; auto-merge; elements = { ${ssh4_elems} } }
    set allow_https      { type ipv4_addr; flags interval; auto-merge; elements = { ${NFT_DEFAULT_V4} } }
    set allow_syslog     { type ipv4_addr; flags interval; auto-merge; elements = { ${NFT_DEFAULT_V4} } }
    set allow_syslog_tls { type ipv4_addr; flags interval; auto-merge; elements = { ${NFT_DEFAULT_V4} } }
    set allow_wef        { type ipv4_addr; flags interval; auto-merge; elements = { ${NFT_DEFAULT_V4} } }
    set allow_wef_https  { type ipv4_addr; flags interval; auto-merge; }
    set allow_snmptrap   { type ipv4_addr; flags interval; auto-merge; elements = { ${NFT_DEFAULT_V4} } }

    # Quell-Freigaben je Dienst (IPv6)
    set allow_ssh6        { type ipv6_addr; flags interval; auto-merge; elements = { ${ssh6_elems} } }
    set allow_https6      { type ipv6_addr; flags interval; auto-merge; elements = { ${NFT_DEFAULT_V6} } }
    set allow_syslog6     { type ipv6_addr; flags interval; auto-merge; }
    set allow_syslog_tls6 { type ipv6_addr; flags interval; auto-merge; }
    set allow_wef6        { type ipv6_addr; flags interval; auto-merge; }
    set allow_wef_https6  { type ipv6_addr; flags interval; auto-merge; }
    set allow_snmptrap6   { type ipv6_addr; flags interval; auto-merge; }

    chain input {
        type filter hook input priority filter; policy drop;

        iif "lo" accept
        ct state established,related accept
        ct state invalid drop

        # ICMP / ICMPv6 (Neighbor Discovery ist für IPv6 zwingend)
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 20/second accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept

        # DHCP-Antworten (falls die Management-Adresse per DHCP bezogen wird)
        udp sport 67 udp dport 68 accept

        # Verwaltung (mit Begrenzung neuer Verbindungen)
        tcp dport 22  ip  saddr @allow_ssh   ct state new limit rate 30/minute burst 20 packets accept
        tcp dport 22  ip6 saddr @allow_ssh6  ct state new limit rate 30/minute burst 20 packets accept
        tcp dport 443 ip  saddr @allow_https  ct state new limit rate 600/minute burst 200 packets accept
        tcp dport 443 ip6 saddr @allow_https6 ct state new limit rate 600/minute burst 200 packets accept

        # Log-Empfang
        udp dport 514  ip  saddr @allow_syslog      accept
        tcp dport 514  ip  saddr @allow_syslog      accept
        udp dport 514  ip6 saddr @allow_syslog6     accept
        tcp dport 514  ip6 saddr @allow_syslog6     accept
        tcp dport 6514 ip  saddr @allow_syslog_tls  accept
        tcp dport 6514 ip6 saddr @allow_syslog_tls6 accept
        tcp dport 5985 ip  saddr @allow_wef         accept
        tcp dport 5985 ip6 saddr @allow_wef6        accept
        tcp dport 5986 ip  saddr @allow_wef_https   accept
        tcp dport 5986 ip6 saddr @allow_wef_https6  accept
        udp dport 162  ip  saddr @allow_snmptrap    accept
        udp dport 162  ip6 saddr @allow_snmptrap6   accept

        limit rate 10/minute log prefix "siem-fw-drop: " level info
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        # Nur ausgehender Verkehr der Appliance-Container (Updates, Mail, Teams, APIs)
        iifname "${SIEM_BRIDGE}" oifname != "${SIEM_BRIDGE}" accept
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF
}
