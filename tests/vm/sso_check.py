#!/usr/bin/env python3
"""SSO-Ende-zu-Ende-Prüfung (VM-Test): Web-Admin → TOTP einrichten → OpenSearch Dashboards.

Aufruf: sso_check.py BASIS-URL BENUTZER KENNWORT
Ausgabe: je Prüfung "OK …" oder "FAIL …"; Exit 1 bei Fehlern. Nur Standardbibliothek.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookiejar
import json
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request

BASE, USER, PASSWORD = sys.argv[1], sys.argv[2], sys.argv[3]
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # Test gegen 127.0.0.1 (Zertifikat wird im VM-Test separat geprüft)
failed = False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


def opener(jar: http.cookiejar.CookieJar | None = None):
    handlers = [urllib.request.HTTPSHandler(context=CTX), NoRedirect()]
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    return urllib.request.build_opener(*handlers)


def call(op, method, path, body=None, headers=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body else None)  # noqa: S310
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with op.open(req, timeout=30) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def totp(secret: str, t: float) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(t // 30)), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def check(ok: bool, text: str, extra: str = "") -> None:
    global failed
    print(("OK   " if ok else "FAIL ") + text + ("" if ok else f" – {extra[:400]}"))
    failed |= not ok


anon = opener()
st, hd, _ = call(anon, "GET", "/dashboards/app/home")
check(st == 302 and hd.get("Location", "").endswith("/"), "Dashboards ohne Anmeldung → Weiterleitung zur Anmeldung", f"{st}")

forged = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbImFsbF9hY2Nlc3MiXX0.AAAA"
st, _, _ = call(anon, "GET", "/dashboards/api/v1/auth/authinfo", headers={"Authorization": f"Bearer {forged}"})
check(st in (302, 401), "selbst gesetztes JWT wird nicht durchgereicht", f"{st}")

jar = http.cookiejar.CookieJar()
op = opener(jar)
st, _, body = call(op, "POST", "/api/auth/login", {"username": USER, "password": PASSWORD})
me = json.loads(body or b"{}")
check(st == 200 and me.get("stage") == "mfa_enroll", "Anmeldung Web-Admin (2FA-Einrichtung verlangt)", f"{st} {body!r}")
csrf = {"X-CSRF-Token": me.get("csrf_token", "")}

st, _, _ = call(op, "GET", "/dashboards/app/home")
check(st == 302, "Dashboards vor abgeschlossener 2FA gesperrt (Weiterleitung)", f"{st}")

st, _, body = call(op, "POST", "/api/auth/totp/setup", headers=csrf)
secret = json.loads(body or b"{}").get("secret", "")
st, _, body = call(op, "POST", "/api/auth/totp/enable", {"code": totp(secret, time.time())}, headers=csrf)
check(st == 200 and json.loads(body).get("stage") == "ok", "TOTP eingerichtet, Anmeldung vollständig", f"{st} {body!r}")

st, _, body = call(op, "GET", "/dashboards/api/v1/auth/authinfo")
info = json.loads(body or b"{}") if st == 200 else {}
check(st == 200 and info.get("user_name") == USER and "siem_reader" in info.get("backend_roles", []),
      "Dashboards erkennt den Benutzer per SSO (Rolle siem_reader)", f"{st} {body[:300]!r}")
st, _, _ = call(op, "GET", "/dashboards/app/home")
check(st == 200, "Dashboards-Oberfläche erreichbar", f"{st}")

st, _, _ = call(op, "POST", "/api/auth/logout", headers=csrf)
st, _, _ = call(op, "GET", "/dashboards/app/home")
check(st == 302, "nach Abmeldung kein Zugriff mehr auf Dashboards", f"{st}")
sys.exit(1 if failed else 0)
