"""Minimales HS256-JWT für das SSO zu OpenSearch Dashboards (keine Fremdbibliothek nötig)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_hs256(key: bytes, claims: dict) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


def dashboards_token(key: bytes, username: str, roles: list[str], ttl: int = 300) -> str:
    now = int(time.time())
    return sign_hs256(key, {"sub": username, "roles": roles, "iat": now, "nbf": now - 5, "exp": now + ttl,
                            "iss": "kmu-siem"})
