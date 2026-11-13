# shellcheck shell=bash
# Interne PKI der Appliance: Root-CA und Zertifikate je Dienst.
# Jeder Dienst erhält nur sein eigenes Schlüsselpaar (eigenes Verzeichnis, eigener Besitzer).
# Idempotent: vorhandene Schlüssel/Zertifikate werden nicht neu erzeugt.

: "${PKI_DIR:=$SIEM_ROOT/data/secrets/pki}"
readonly PKI_CA_DAYS=3650
readonly PKI_LEAF_DAYS=825

# Container-Benutzer (UID:GID) der Dienste
readonly UID_OPENSEARCH=1000
readonly UID_VECTOR=2000
# shellcheck disable=SC2034  # genutzt in step_app.sh
readonly UID_API=2100
readonly UID_PROXY=101

pki_ensure() {
    local fqdn=${ANSWERS[SIEM_FQDN]:-$(probe_fqdn)} san ip
    install -d -m 0700 "$PKI_DIR" || return 1
    _pki_ca "$fqdn" || return 1

    # Server-SAN: FQDN, Kurzname, alle globalen IPv4-Adressen, localhost
    san="DNS:$fqdn,DNS:${fqdn%%.*},DNS:localhost,IP:127.0.0.1"
    while read -r _ ip _; do san+=",IP:${ip%/*}"; done < <(probe_ipv4)

    _pki_leaf opensearch "/O=kmu-siem/OU=siem/CN=opensearch" "DNS:opensearch,DNS:localhost,IP:127.0.0.1" || return 1
    _pki_leaf admin "/O=kmu-siem/OU=siem/CN=siem-admin" "DNS:siem-admin" || return 1
    _pki_leaf syslog "/O=kmu-siem/OU=siem/CN=$fqdn" "$san" || return 1
    _pki_leaf web "/O=kmu-siem/OU=siem/CN=$fqdn" "$san" || return 1

    # Verteilung je Dienst (nur eigene Dateien, Besitzer = Container-Benutzer)
    _pki_deploy opensearch "$UID_OPENSEARCH" \
        "opensearch.crt:node.pem" "opensearch.key:node-key.pem" "ca.crt:ca.pem" || return 1
    _pki_deploy vector "$UID_VECTOR" \
        "syslog.crt:syslog.crt" "syslog.key:syslog.key" "ca.crt:ca.crt" || return 1
    _pki_deploy proxy "$UID_PROXY" \
        "web.chain.crt:web.crt" "web.key:web.key" || return 1
}

_pki_ca() {
    local fqdn=$1
    [[ -s $PKI_DIR/ca.key && -s $PKI_DIR/ca.crt ]] && return 0
    ( umask 077
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$PKI_DIR/ca.key" 2>>"$SIEM_LOG_FILE" ) || return 1
    openssl req -x509 -new -key "$PKI_DIR/ca.key" -sha256 -days "$PKI_CA_DAYS" \
        -subj "/O=kmu-siem/OU=siem/CN=KMU-SIEM Root CA ${fqdn}" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -out "$PKI_DIR/ca.crt" 2>>"$SIEM_LOG_FILE" || return 1
    chmod 0644 "$PKI_DIR/ca.crt"
    log INFO "Root-CA erzeugt"
}

# _pki_leaf NAME SUBJEKT SAN
_pki_leaf() {
    local name=$1 subj=$2 san=$3 ext
    [[ -s $PKI_DIR/$name.key && -s $PKI_DIR/$name.crt ]] && return 0
    ( umask 077
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$PKI_DIR/$name.key" 2>>"$SIEM_LOG_FILE" ) || return 1
    openssl req -new -key "$PKI_DIR/$name.key" -subj "$subj" -out "$PKI_DIR/$name.csr" 2>>"$SIEM_LOG_FILE" || return 1
    ext=$(mktemp) || return 1
    cat >"$ext" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = $san
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
    openssl x509 -req -in "$PKI_DIR/$name.csr" -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" \
        -CAcreateserial -days "$PKI_LEAF_DAYS" -sha256 -extfile "$ext" \
        -out "$PKI_DIR/$name.crt" 2>>"$SIEM_LOG_FILE" || { rm -f "$ext"; return 1; }
    rm -f "$ext" "$PKI_DIR/$name.csr"
    cat "$PKI_DIR/$name.crt" "$PKI_DIR/ca.crt" >"$PKI_DIR/$name.chain.crt"
    log INFO "Zertifikat erzeugt: $name ($subj)"
}

# _pki_deploy ZIEL UID QUELLE:ZIELNAME…
_pki_deploy() {
    local target=$1 uid=$2 dir="$PKI_DIR/$1" pair src dst
    shift 2
    install -d -m 0500 -o "$uid" -g "$uid" "$dir" || return 1
    for pair in "$@"; do
        src=${pair%%:*}; dst=${pair#*:}
        if ! cmp -s "$PKI_DIR/$src" "$dir/$dst" 2>/dev/null; then
            install -m 0400 -o "$uid" -g "$uid" "$PKI_DIR/$src" "$dir/$dst" || return 1
        fi
    done
    log INFO "Zertifikate bereitgestellt: $target"
}

# pki_fingerprint DATEI – SHA-256-Fingerabdruck
pki_fingerprint() {
    openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}
