# shellcheck shell=bash
# Schritt "selftest": Abschluss-Selbsttest der Installation (SPEC 4.1, Schritt 10).
#   - Container laufen, OpenSearch erreichbar
#   - Ende-zu-Ende: Syslog über TCP, UDP und TLS erscheint in OpenSearch (< 10 s)
#   - Proxy: HTTPS mit TLS 1.3, Sicherheits-Header, /health
# Phase 1.4 ergänzt AIDE-Initialisierung und Lynis-Prüfung.

readonly SELFTEST_TIMEOUT=10

step_selftest() {
    _st_containers || return 1
    _st_syslog tcp || return 1
    _st_syslog udp || return 1
    _st_syslog tls || return 1
    _st_proxy || return 1
    ok "$(msg selftest_ok)"
}

_st_containers() {
    local c state
    for c in siem-opensearch siem-vector siem-proxy; do
        state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)
        if [[ $state != running ]]; then
            err "$(msg selftest_container "$c" "${state:-fehlt}")"
            return 1
        fi
    done
}

# _st_syslog tcp|udp|tls – Testereignis senden und in OpenSearch suchen
_st_syslog() {
    local proto=$1 id line res
    id="selftest-$(date +%s)-$RANDOM-$proto"
    line="<14>1 $(date -u +%Y-%m-%dT%H:%M:%SZ) $(hostname) siem-selftest - - - SIEM-SELFTEST $id"
    case $proto in
        tcp) printf '%s\n' "$line" >/dev/tcp/127.0.0.1/10514 || return 1 ;;
        udp) printf '%s\n' "$line" >/dev/udp/127.0.0.1/10514 || return 1 ;;
        tls) { printf '%s\n' "$line"; sleep 1; } \
                 | timeout 10 openssl s_client -connect 127.0.0.1:6514 -quiet \
                     -CAfile "$SECRETS_DIR/pki/ca.crt" -verify_return_error >/dev/null 2>>"$SIEM_LOG_FILE" || true ;;
    esac
    if res=$(siem_os_init find --index 'siem-system-*' --text "$id" --timeout "$SELFTEST_TIMEOUT"); then
        ok "$(msg selftest_syslog "${proto^^}" "$(sed -E 's/.*"seconds": ([0-9.]+).*/\1/' <<<"$res")")"
        return 0
    fi
    err "$(msg selftest_syslog_fail "${proto^^}" "$SELFTEST_TIMEOUT")"
    _st_diagnose
    return 1
}

# Diagnose bei Fehlschlag: letzte Log-Zeilen der beteiligten Dienste (auch ins Protokoll)
_st_diagnose() {
    local c
    for c in siem-vector siem-opensearch; do
        printf '\n--- %s (letzte Zeilen) ---\n' "$c" >&2
        docker logs --tail 25 "$c" 2>&1 | tee -a "$SIEM_LOG_FILE" >&2
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
    ok "$(msg selftest_proxy)"
}
