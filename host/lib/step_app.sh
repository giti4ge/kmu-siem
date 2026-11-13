# shellcheck shell=bash
# Schritt "app": Anwendungs-Stack bereitstellen und starten.
#   - Bundle nach /opt/siem/app/<version>, Verweis /opt/siem/app/current
#   - Datenverzeichnisse mit Besitzern der Container-Benutzer
#   - Geheimnisse (OpenSearch-Admin, Vector), interne Benutzer für OpenSearch
#   - PKI, Laufzeitkonfiguration (Heap), Images laden (per Digest), Start
#   - OpenSearch: Templates und ISM-Richtlinien je Kategorie

readonly APP_DIR="$SIEM_ROOT/app"
readonly APP_DATA="$SIEM_ROOT/data/app"
readonly SECRETS_DIR="$SIEM_ROOT/data/secrets"

siem_compose() {
    docker compose -p siem -f "$APP_DIR/current/docker-compose.yml" --env-file "$APP_DATA/app.env" "$@"
}

siem_os_init() {
    /usr/bin/python3 -I "$APP_DIR/current/opensearch/init.py" --ca "$SECRETS_DIR/pki/ca.crt" \
        --password-file "$SECRETS_DIR/opensearch-admin.pw" "$@"
}

step_app() {
    _app_bundle || return 1
    _app_dirs || return 1
    _app_secrets || return 1
    pki_ensure || return 1
    _app_env || return 1
    _app_load_images || return 1
    # Nur fehlende Images holen (per Digest festgeschrieben bzw. aus dem Bundle geladen)
    run_cmd "Container-Images laden" siem_compose pull --quiet --policy missing || return 1
    run_cmd "Anwendung starten" siem_compose up -d --remove-orphans || return 1
    run_cmd "Auf OpenSearch warten" siem_os_init wait --timeout 300 || return 1
    run_cmd "Index-Templates und Aufbewahrung anwenden" siem_os_init apply || return 1
    run_cmd "SSO für Dashboards einrichten" siem_os_init security \
        --jwt-key-file "$SECRETS_DIR/control-plane/dashboards-jwt.key" \
        --kibanaserver-password-file "$SECRETS_DIR/kibanaserver.pw" || return 1
    _app_admin || return 1
}

# Dashboards: Dienstkonto, Cookie-Schlüssel, JWT-Schlüssel (geteilt mit der Control-Plane)
_app_dashboards_secrets() {
    local kpw="$SECRETS_DIR/kibanaserver.pw" cpw="$SECRETS_DIR/dashboards-cookie.pw"
    local jwt="$SECRETS_DIR/control-plane/dashboards-jwt.key" envf="$SECRETS_DIR/dashboards/dashboards.env" rc
    _gen_password "$kpw" || return 1
    _gen_password "$cpw" || return 1
    if [[ ! -s $jwt ]]; then
        ( umask 077; openssl rand -base64 32 >"$jwt" ) || return 1
    fi
    chown "$UID_API:$UID_API" "$jwt" && chmod 0400 "$jwt" || return 1
    printf 'KIBANASERVER_PASSWORD=%s\nCOOKIE_PASSWORD=%s\n' "$(cat "$kpw")" "$(cat "$cpw")" \
        | write_file "$envf" 0400
    rc=$?; (( rc <= 1 )) || return 1
    chmod 0700 "$SECRETS_DIR/dashboards"
}

# Im Bundle mitgelieferte Images (images/<name>.tar + <name>.ref) laden, falls nicht vorhanden
_app_load_images() {
    local tar ref
    for tar in "$APP_DIR/current/images/"*.tar; do
        [[ -f $tar ]] || continue
        ref=$(cat "${tar%.tar}.ref" 2>/dev/null) || ref=""
        if [[ -n $ref ]] && docker image inspect "$ref" >/dev/null 2>&1; then
            continue
        fi
        run_cmd "Image laden: ${tar##*/}" docker load -q -i "$tar" || return 1
    done
}

# Ersten Web-Administrator anlegen (Kennwort aus den Installationsfragen), danach Geheimnis löschen
_app_admin() {
    local secret="$SIEM_STATE_DIR/secrets/web_admin_password" i
    for (( i = 0; i < 60; i++ )); do
        [[ $(docker inspect -f '{{.State.Health.Status}}' siem-api 2>/dev/null) == healthy ]] && break
        sleep 2
    done
    [[ $(docker inspect -f '{{.State.Health.Status}}' siem-api 2>/dev/null) == healthy ]] \
        || { err "Control-Plane (siem-api) nicht bereit"; return 1; }
    [[ -f $secret ]] || return 0
    run_cmd "Web-Administrator anlegen" docker exec -i siem-api python -m siem_api.cli create-admin \
        --username admin --password-stdin <"$secret" || return 1
    shred -u "$secret" 2>/dev/null || rm -f "$secret"
}

# Bundle des laufenden Installers übernehmen (bei Lauf aus /opt/siem/host: vorhandenes "current")
_app_bundle() {
    local src="$SIEM_HOST_DIR/../app" ver=${SIEM_VERSION:-unknown} dst
    dst="$APP_DIR/$ver"
    if [[ -f $src/docker-compose.yml ]]; then
        if [[ ! -d $dst ]] || ! diff -rq "$src" "$dst" >/dev/null 2>&1; then
            install -d -m 0755 "$APP_DIR" || return 1
            rm -rf "$dst.new"
            cp -a "$src" "$dst.new" || return 1
            chown -R root:root "$dst.new"
            chmod -R go-w "$dst.new"
            rm -rf "$dst"
            mv "$dst.new" "$dst" || return 1
            log INFO "Anwendung $ver nach $dst übernommen"
        fi
        ln -sfn "$ver" "$APP_DIR/current"
    fi
    [[ -f $APP_DIR/current/docker-compose.yml ]] || { err "Anwendungs-Bundle fehlt ($src)"; return 1; }
}

_app_dirs() {
    install -d -m 0750 -o "$UID_OPENSEARCH" -g "$UID_OPENSEARCH" \
        "$SIEM_ROOT/data/opensearch" "$SIEM_ROOT/data/opensearch-snapshots" || return 1
    install -d -m 0750 -o "$UID_VECTOR" -g "$UID_VECTOR" "$SIEM_ROOT/data/vector-buffer" || return 1
    # Control-Plane: Config-DB und eigene Schlüssel (Master-Key, Audit-Schlüssel)
    install -d -m 0750 -o "$UID_API" -g "$UID_API" "$SIEM_ROOT/data/config-db" || return 1
    install -d -m 0700 -o "$UID_API" -g "$UID_API" "$SECRETS_DIR/control-plane" || return 1
    # OpenWEC: Konfiguration/Keytab/Subscriptions schreibt die Control-Plane (uid 2100), openwecd liest (gid 2100)
    install -d -m 0750 -o "$UID_API" -g "$UID_API" "$SIEM_ROOT/data/openwec/conf" || return 1
    install -d -m 0750 -o "$UID_OPENWEC" -g "$UID_OPENWEC" "$SIEM_ROOT/data/openwec/db" || return 1
    install -d -m 0750 "$APP_DATA" || return 1
    install -d -m 0750 -o root -g "$UID_OPENSEARCH" "$APP_DATA/opensearch-security" || return 1
}

# _gen_password DATEI – zufälliges Kennwort, nur wenn nicht vorhanden
_gen_password() {
    [[ -s $1 ]] && return 0
    ( umask 077; openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 40 >"$1" ) || return 1
    [[ -s $1 ]]
}

_app_secrets() {
    local admin_pw="$SECRETS_DIR/opensearch-admin.pw" vector_pw="$SECRETS_DIR/vector.pw"
    local users="$APP_DATA/opensearch-security/internal_users.yml" sumfile sum
    install -d -m 0700 "$SECRETS_DIR" || return 1
    _gen_password "$admin_pw" || return 1
    _gen_password "$vector_pw" || return 1
    _app_dashboards_secrets || return 1

    # internal_users.yml nur neu erzeugen, wenn sich ein Kennwort geändert hat
    sumfile="$APP_DATA/opensearch-security/.pwsum"
    sum=$(cat "$admin_pw" "$vector_pw" | sha256sum | cut -d' ' -f1)
    if [[ ! -s $users || $(cat "$sumfile" 2>/dev/null) != "$sum" ]]; then
        local h_admin h_vector
        h_admin=$(htpasswd -niBC 12 admin <"$admin_pw" | cut -d: -f2-) || return 1
        h_vector=$(htpasswd -niBC 12 vector <"$vector_pw" | cut -d: -f2-) || return 1
        write_file "$users" 0440 "$UID_OPENSEARCH:$UID_OPENSEARCH" <<EOF
# Von install.sh verwaltet – interne Benutzer von OpenSearch
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "${h_admin}"
  reserved: true
  description: "KMU-SIEM Administrator (intern)"

vector:
  hash: "${h_vector}"
  reserved: true
  description: "Ingest (Vector)"
EOF
        (( $? <= 1 )) || return 1
        printf '%s\n' "$sum" >"$sumfile"
    fi
    # Vector liest das Kennwort über sein Secrets-Backend (Datei, nur für den Vector-Benutzer)
    install -d -m 0500 -o "$UID_VECTOR" -g "$UID_VECTOR" "$SECRETS_DIR/vector" || return 1
    printf '{"opensearch_password": "%s"}\n' "$(cat "$vector_pw")" \
        | write_file "$SECRETS_DIR/vector/secrets.json" 0400 "$UID_VECTOR:$UID_VECTOR"
    (( $? <= 1 )) || return 1
    rm -f "$APP_DATA/vector.env"
}

# OpenSearch-Heap: ¼ des RAM, mindestens 1 GB, höchstens 6 GB (SPEC 1.1)
_app_heap_gb() {
    local kb gb heap
    if [[ -n ${SIEM_OPENSEARCH_HEAP_GB:-} ]]; then printf '%s' "$SIEM_OPENSEARCH_HEAP_GB"; return; fi
    kb=$(probe_mem_kb)
    gb=$(( (kb + 524288) / 1048576 ))
    heap=$(( gb / 4 ))
    (( heap < 1 )) && heap=1
    (( heap > 6 )) && heap=6
    printf '%s' "$heap"
}

_app_env() {
    local heap
    heap=$(_app_heap_gb)
    write_file "$APP_DATA/app.env" 0640 <<EOF
# Von install.sh verwaltet – Laufzeitkonfiguration des Anwendungs-Stacks
SIEM_DATA=$SIEM_ROOT/data
OPENSEARCH_JAVA_OPTS=-Xms${heap}g -Xmx${heap}g
SIEM_API_IMAGE=ghcr.io/giti4ge/kmu-siem/api:${SIEM_VERSION:-dev}
SIEM_OPENWEC_IMAGE=ghcr.io/giti4ge/kmu-siem/openwec:${SIEM_VERSION:-dev}
SIEM_HOSTD_GID=$(getent group siem-hostd | cut -d: -f3)
EOF
    (( $? <= 1 ))
}
