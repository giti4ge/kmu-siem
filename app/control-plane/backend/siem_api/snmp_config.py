"""SNMP-Zugangsdaten für den Trap-Empfänger (v2c-Communities, v3-Benutzer); Geheimnisse AES-256-GCM-verschlüsselt."""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from typing import Any

from .security import crypto

AUTH_PROTOS = ("sha", "sha256")
PRIV_PROTOS = ("none", "aes128", "aes256")
_USER = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_ENGINE_ID = re.compile(r"^(0x)?([0-9A-Fa-f]{2}){5,32}$")
_COMMUNITY = re.compile(r"^[A-Za-z0-9._@!#%^*+=-]{8,64}$")
MAX_ENTRIES = 50


class SnmpConfigError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def config_path(secrets_dir: Path) -> Path:
    return secrets_dir / "snmp.json"


def _enc(key: bytes, value: str, ctx: str) -> str:
    return base64.b64encode(crypto.encrypt(key, value, ctx)).decode()


def _dec(key: bytes, blob: str, ctx: str) -> str:
    return crypto.decrypt(key, base64.b64decode(blob), ctx)


def _read(secrets_dir: Path) -> dict[str, Any]:
    try:
        return json.loads(config_path(secrets_dir).read_text("utf-8"))
    except (OSError, ValueError):
        return {"communities": [], "v3_users": []}


def _write(secrets_dir: Path, data: dict[str, Any]) -> None:
    p = config_path(secrets_dir)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, p)


def view(secrets_dir: Path) -> dict[str, Any]:
    """Ohne Geheimnisse: Anzahl Communities, v3-Benutzer mit Protokollen."""
    d = _read(secrets_dir)
    return {"communities": len(d.get("communities", [])),
            "v3_users": [{"user": u["user"], "auth_proto": u["auth_proto"], "priv_proto": u["priv_proto"],
                          "engine_id": u.get("engine_id", "")} for u in d.get("v3_users", [])]}


def save(secrets_dir: Path, master_key: bytes, communities: list[str] | None, v3_users: list[dict[str, Any]]) -> None:
    """``communities=None`` lässt die vorhandenen unverändert; v3-Benutzer ohne Schlüssel behalten ihren alten."""
    old = _read(secrets_dir)
    if len(v3_users) > MAX_ENTRIES or (communities and len(communities) > MAX_ENTRIES):
        raise SnmpConfigError("snmp_too_many")
    if communities is None:
        enc_comm = old.get("communities", [])
    else:
        if not all(_COMMUNITY.match(c) for c in communities):
            raise SnmpConfigError("snmp_invalid_community")
        enc_comm = [_enc(master_key, c, "snmp.community") for c in communities]
    old_users = {u["user"]: u for u in old.get("v3_users", [])}
    users = []
    for u in v3_users:
        name = str(u.get("user", ""))
        if not _USER.match(name) or u.get("auth_proto") not in AUTH_PROTOS or u.get("priv_proto") not in PRIV_PROTOS:
            raise SnmpConfigError("snmp_invalid_user")
        prev = old_users.get(name)
        engine_id = str(u.get("engine_id") or "").strip()
        if engine_id and not _ENGINE_ID.match(engine_id):
            raise SnmpConfigError("snmp_invalid_engine_id")
        entry = {"user": name, "auth_proto": u["auth_proto"], "priv_proto": u["priv_proto"],
                 "engine_id": engine_id.lower().removeprefix("0x")}
        for field, ctx in (("auth_key", "snmp.auth"), ("priv_key", "snmp.priv")):
            val = u.get(field)
            if field == "priv_key" and u["priv_proto"] == "none":
                entry[field] = ""
            elif val:
                if len(val) < 8 or len(val) > 128:
                    raise SnmpConfigError("snmp_invalid_key")
                entry[field] = _enc(master_key, val, f"{ctx}.{name}")
            elif prev and prev.get(field):
                entry[field] = prev[field]
            else:
                raise SnmpConfigError("snmp_invalid_key")
        users.append(entry)
    if len({u["user"] for u in users}) != len(users):
        raise SnmpConfigError("snmp_invalid_user")
    _write(secrets_dir, {"communities": enc_comm, "v3_users": users})


def load_runtime(secrets_dir: Path, master_key: bytes) -> dict[str, Any]:
    d = _read(secrets_dir)
    return {
        "communities": [_dec(master_key, c, "snmp.community") for c in d.get("communities", [])],
        "v3_users": [{"user": u["user"], "auth_proto": u["auth_proto"], "priv_proto": u["priv_proto"],
                      "engine_id": u.get("engine_id", ""),
                      "auth_key": _dec(master_key, u["auth_key"], f"snmp.auth.{u['user']}"),
                      "priv_key": (_dec(master_key, u["priv_key"], f"snmp.priv.{u['user']}")
                                   if u.get("priv_key") else "")}
                     for u in d.get("v3_users", [])],
    }


def protocol_objects() -> dict[str, dict[str, Any]]:
    from pysnmp.entity import config
    return {
        "auth": {"sha": config.USM_AUTH_HMAC96_SHA, "sha256": config.USM_AUTH_HMAC192_SHA256},
        "priv": {"aes128": config.USM_PRIV_CFB128_AES, "aes256": config.USM_PRIV_CFB256_AES},
    }
