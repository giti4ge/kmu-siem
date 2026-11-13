# shellcheck shell=bash
# Schritt "selftest": Abschluss-Selbsttest der Installation (SPEC 4.1, Schritt 10).
#   - Container laufen, OpenSearch erreichbar
#   - Ende-zu-Ende: Syslog über TCP, UDP und TLS erscheint in OpenSearch (< 10 s)
#   - Proxy: HTTPS mit TLS 1.3, Sicherheits-Header, /health
# Phase 1.4 ergänzt AIDE-Initialisierung und Lynis-Prüfung.

readonly SELFTEST_TIMEOUT=30  # Vector kann kurz nach Sicherheits-Neuladen von OpenSearch im Retry-Backoff sein
# Erster Test nach (Neu-)Start: Vector kann nach OpenSearch-Neustart im Retry-Backoff sein
readonly SELFTEST_WARMUP=90
: "${SIEM_MIN_LYNIS:=80}"

step_selftest() {
    _st_containers || return 1
    _st_syslog tcp "$SELFTEST_WARMUP" || return 1
    _st_syslog udp || return 1
    _st_syslog tls || return 1
    _st_proxy || return 1
    _st_integrity || return 1
    _st_lynis
    ok "$(msg selftest_ok)"
}

# Integritätsprüfung: AIDE-Datenbank (nach allen Dateiänderungen), tägliche Prüfung, rkhunter
_st_integrity() {
    local rc
    # Veränderliche Daten nicht überwachen (Ereignisse, Container, Zustand, Protokolle)
    write_file /etc/aide/aide.conf.d/99_siem_excludes 0644 <<'EOF'
# Von install.sh verwaltet – veränderliche Bereiche der Appliance
!/opt/siem/data
!/opt/siem/backups
!/var/lib/docker
!/var/lib/containerd
!/var/lib/siem
!/var/lib/sysstat
!/var/lib/rkhunter
!/var/lib/chrony
!/var/log
!/var/cache
!/var/tmp
!/run
!/tmp
EOF
    rc=$?; (( rc <= 1 )) || return 1
    if [[ ! -s /var/lib/aide/aide.db ]]; then
        info "$(msg aide_init)"
        if command -v aideinit >/dev/null; then
            run_cmd "AIDE-Datenbank initialisieren" aideinit -y -f || return 1
        else
            run_cmd "AIDE-Datenbank initialisieren" aide --init --config /etc/aide/aide.conf || return 1
            mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db || return 1
        fi
    fi
    systemctl enable --now dailyaidecheck.timer >/dev/null 2>&1 || true
    if command -v rkhunter >/dev/null && [[ ! -s /var/lib/rkhunter/db/rkhunter.dat ]]; then
        run_cmd "rkhunter-Datenbank anlegen" rkhunter --propupd --nocolors || true
    fi
    ok "$(msg integrity_ok)"
}

# Lynis-Härtungsprüfung: Ergebnis melden (Warnung unter Zielwert, kein Abbruch)
_st_lynis() {
    local idx
    command -v lynis >/dev/null || return 0
    run_cmd "Lynis-Prüfung" lynis audit system --quick --no-colors --cronjob >/dev/null || true
    idx=$(awk -F= '/^hardening_index=/ { print $2 }' /var/log/lynis-report.dat 2>/dev/null)
    [[ $idx =~ ^[0-9]+$ ]] || { warn "$(msg lynis_unknown)"; return 0; }
    if (( idx >= SIEM_MIN_LYNIS )); then
        ok "$(msg lynis_index "$idx" "$SIEM_MIN_LYNIS")"
    else
        warn "$(msg lynis_index "$idx" "$SIEM_MIN_LYNIS")"
    fi
}

_st_containers() {
    local c state
    for c in siem-opensearch siem-vector siem-proxy siem-api siem-dashboards; do
        state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)
        if [[ $state != running ]]; then
            err "$(msg selftest_container "$c" "${state:-fehlt}")"
            return 1
        fi
    done
}

# _st_syslog tcp|udp|tls [Timeout] – Testereignis senden und in OpenSearch suchen
_st_syslog() {
    local proto=$1 tmo=${2:-$SELFTEST_TIMEOUT} id line res try per=30 tries
    id="selftest-$(date +%s)-$RANDOM-$proto"
    tries=$(( (tmo + per - 1) / per ))
    # Ein Ereignis kann beim Sicherheits-Neuladen von OpenSearch (401) verworfen werden → erneut senden
    for (( try = 1; try <= tries; try++ )); do
        line="<14>1 $(date -u +%Y-%m-%dT%H:%M:%SZ) $(hostname) siem-selftest - - - SIEM-SELFTEST $id"
        case $proto in
            tcp) printf '%s
' "$line" >/dev/tcp/127.0.0.1/10514 || return 1 ;;
            udp) printf '%s
' "$line" >/dev/udp/127.0.0.1/10514 || return 1 ;;
            tls) { printf '%s
' "$line"; sleep 1; }                      | timeout 10 openssl s_client -connect 127.0.0.1:6514 -quiet                          -CAfile "$SECRETS_DIR/pki/ca.crt" -verify_return_error >/dev/null 2>>"$SIEM_LOG_FILE" || true ;;
        esac
        if res=$(siem_os_init find --index 'siem-system-*' --text "$id" --timeout "$(( tmo < per ? tmo : per ))"); then
            ok "$(msg selftest_syslog "${proto^^}" "$(sed -E 's/.*"seconds": ([0-9.]+).*//' <<<"$res")")"
            return 0
        fi
    done
    err "$(msg selftest_syslog_fail "${proto^^}" "$tmo")"
    _st_diagnose "$id"
    return 1
}

# Diagnose bei Fehlschlag: letzte Log-Zeilen der beteiligten Dienste (auch ins Protokoll)
_st_diagnose() {
    local c
    {
        printf '
--- Ereignis in anderen Indizes? (%s) ---
' "${1:-}"
        [[ -n ${1:-} ]] && siem_os_init find --index 'siem-*' --text "$1" --timeout 3 2>&1
        docker exec siem-opensearch curl -s --max-time 5 -o /dev/null -w 'OpenSearch ohne Zugangsdaten: HTTP %{http_code}
' https://localhost:9200 -k 2>&1
    } | tee -a "$SIEM_LOG_FILE" >&2
    {
        printf '\n--- Netzwerk: Listener und Umleitungen ---\n'
        ss -ltnup 2>&1 | grep -E ':(514|6514|10514|9200)\b'
        nft list ruleset 2>&1 | grep -E 'redirect|dport (514|6514)'
        docker ps -a --format '{{.Names}}: {{.Status}}' 2>&1
    } | tee -a "$SIEM_LOG_FILE" >&2
    for c in siem-vector siem-opensearch; do
        printf '\n--- %s (letzte Zeilen) ---\n' "$c" >&2
        docker logs --since 10m --tail 80 "$c" 2>&1 | tee -a "$SIEM_LOG_FILE" >&2
    done
}

_st_proxy() {
    local fqdn=${ANSWERS[SIEM_FQDN]:-$(probe_fqdn)} headers body i
    for (( i = 0; i < 15; i++ )); do
        body=$(curl -s --max-time 5 --tlsv1.3 --cacert "$SECRETS_DIR/pki/ca.crt" \
            --resolve "$fqdn:8443:127.0.0.1" -D "$SIEM_STATE_DIR/.st-headers" "https://$fqdn:8443/health" 2>/dev/null) && break
        sleep 2
    done
    headers=$(cat "$SIEM_STATE_DIR/.st-headers" 2>/dev/null); rm -f "$SIEM_STATE_DIR/.st-headers"
    if [[ $body != *'"status":"ok"'* ]]; then
        err "$(msg selftest_proxy_fail)"; return 1
    fi
    if ! grep -qi '^strict-transport-security:' <<<"$headers" || ! grep -qi '^content-security-policy:' <<<"$headers"; then
        err "$(msg selftest_headers_fail)"; return 1
    fi
    # Control-Plane über den Proxy
    body=$(curl -s --max-time 5 --cacert "$SECRETS_DIR/pki/ca.crt" --resolve "$fqdn:8443:127.0.0.1" \
        "https://$fqdn:8443/api/health" 2>/dev/null)
    if [[ $body != *'"status":"ok"'* ]]; then
        err "$(msg selftest_api_fail)"; return 1
    fi
    ok "$(msg selftest_proxy)"
}
