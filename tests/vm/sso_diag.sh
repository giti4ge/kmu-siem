#!/usr/bin/env bash
# SSO-Diagnose (läuft in der VM als root): Welche Schicht lehnt das JWT ab?
# JWT wird mit dem echten Installationsschlüssel signiert und direkt geprüft gegen
# OpenSearch (authinfo) und Dashboards (mit und ohne "Bearer").
S=/opt/siem/data/secrets
T=$(python3 - "$S/control-plane/dashboards-jwt.key" <<'EOF'
import base64, hashlib, hmac, json, sys, time
key = base64.b64decode(open(sys.argv[1]).read().strip())
b = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=").decode()
h = b(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
now = int(time.time())
p = b(json.dumps({"sub": "diag", "roles": ["siem_reader"], "iat": now, "nbf": now - 5, "exp": now + 300,
                  "iss": "kmu-siem"}, separators=(",", ":")).encode())
print(f"{h}.{p}." + b(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()))
EOF
)
pw=$(cat "$S/opensearch-admin.pw")
echo "--- securityconfig authc"
curl -s --cacert "$S/pki/ca.crt" -u "admin:$pw" https://127.0.0.1:9200/_plugins/_security/api/securityconfig \
    | jq -c '.config.dynamic.authc | to_entries[] | {k: .key, order: .value.order, type: .value.http_authenticator.type, cfg: (.value.http_authenticator.config | del(.signing_key)?)}'
echo "--- OpenSearch authinfo mit Bearer-JWT"
curl -s --cacert "$S/pki/ca.crt" -H "Authorization: Bearer $T" https://127.0.0.1:9200/_plugins/_security/authinfo | head -c 400; echo
echo "--- Dashboards authinfo, Header roh"
curl -s -H "Authorization: $T" http://127.0.0.1:5601/dashboards/api/v1/auth/authinfo | head -c 400; echo
echo "--- Dashboards authinfo, Header mit Bearer"
curl -s -H "Authorization: Bearer $T" http://127.0.0.1:5601/dashboards/api/v1/auth/authinfo | head -c 400; echo
echo "--- Dashboards authinfo, URL-Parameter"
curl -s "http://127.0.0.1:5601/dashboards/api/v1/auth/authinfo?authorization=$T" | head -c 400; echo
echo "--- OpenSearch-Log (Security)"
docker logs siem-opensearch 2>&1 | grep -iE "jwt|security\.auth|Exception" | grep -v "No 'Authorization'" | tail -15 | cut -c1-400
