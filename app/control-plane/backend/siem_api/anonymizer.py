"""Pseudonymisierung von Logzeilen (Probenexport, Diagnosepaket, später KI-Bridge, Spec 4.12/4.15).

Ersetzt IPs, MACs, E-Mail-Adressen, Hostnamen und Benutzernamen durch konsistente Platzhalter. Die Platzhalter
behalten das Format (gültige IPv4/IPv6-Adresse, MAC), damit Parser mit den Proben getestet werden können.
Die Zuordnung (Klartext → Platzhalter) bleibt lokal in ``pseudonyms.json`` (0600) und verlässt die Appliance nie.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\w)")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])|(?<![\w:])::(?:[0-9A-Fa-f]{1,4}:?)+")
_MAC = re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_FQDN = re.compile(r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){2,}[A-Za-z]{2,}(?![\w-])")
# Schlüssel=Wert-Paare mit Personen-/Gerätebezug (auch "key: value")
_KEYS = {
    "user": "USER", "username": "USER", "usrname": "USER", "user_name": "USER", "srcuser": "USER", "dstuser": "USER",
    "account": "USER", "accountname": "USER", "login": "USER", "targetusername": "USER", "subjectusername": "USER",
    "hostname": "HOST", "host": "HOST", "devname": "HOST", "srcname": "HOST", "dstname": "HOST", "computer": "HOST",
    "computername": "HOST", "workstation": "HOST", "sysname": "HOST",
}
_KV = re.compile(r"(?i)\b(" + "|".join(sorted(_KEYS, key=len, reverse=True)) + r")(\s*[=:]\s*)(\"[^\"]*\"|\[[^\]]*\]|[^\s,;\"]+)")  # noqa: E501
_PHRASE = [  # freie Formulierungen: "Failed password for <user> from", "Accepted ... for <user>", "user <name>", "User [x]"  # noqa: E501
    (re.compile(r"(?i)\b((?:failed|accepted)\s+\S+\s+for\s+(?:invalid user\s+)?)([^\s]+)(\s+from\b)"), "USER", 2),
    (re.compile(r"(?i)\b(invalid user\s+)([^\s]+)()"), "USER", 2),
    (re.compile(r"(?i)\b(session (?:opened|closed) for user\s+)([^\s(]+)()"), "USER", 2),
    (re.compile(r"(?i)\b(user\s+)\[([^\]]+)\]()"), "USER", 2),
    (re.compile(r"(?i)\b(sudo:\s+)([^\s:]+)(\s*:)"), "USER", 2),
]
_DOMAIN_USER = re.compile(r"\b([A-Za-z0-9-]{2,15})\\([A-Za-z0-9._$-]{1,64})\b")
_SYSLOG_HOST = re.compile(r"^((?:<\d{1,3}>)?(?:\d\s+\S+\s+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+))([A-Za-z0-9][A-Za-z0-9._-]*)(\s)")  # noqa: E501
_KEEP = {"localhost", "-", "root", "system", "nobody", "unknown", "n/a", "none", "null", "admin", "administrator"}


class Pseudonymizer:
    def __init__(self, store: Path | None = None, known_hosts: list[str] | None = None,
                 known_users: list[str] | None = None) -> None:
        self.store = store
        self.lock = threading.Lock()
        self.map: dict[str, str] = {}
        if store and store.exists():
            try:
                data = json.loads(store.read_text("utf-8"))
                self.map = {str(k): str(v) for k, v in data.items()}
            except (OSError, ValueError):
                self.map = {}
        self.known = [(h, "HOST") for h in (known_hosts or []) if h] + [(u, "USER") for u in (known_users or []) if u]
        self.known.sort(key=lambda kv: -len(kv[0]))
        self._dirty = False

    # ---- Platzhalter ----
    def _ph(self, kind: str, value: str) -> str:
        key = f"{kind}|{value.lower()}"
        with self.lock:
            if key not in self.map:
                n = sum(1 for k in self.map if k.startswith(kind + "|")) + 1
                if kind == "IP4":
                    ph = f"10.250.{(n // 250) % 250}.{n % 250 + 1}"
                elif kind == "IP6":
                    ph = f"fd00:250::{n:x}"
                elif kind == "MAC":
                    ph = f"02:00:00:{(n >> 16) & 255:02x}:{(n >> 8) & 255:02x}:{n & 255:02x}"
                else:
                    ph = f"{kind}_{n:02d}"
                self.map[key] = ph
                self._dirty = True
            return self.map[key]

    def save(self) -> None:
        if not (self.store and self._dirty):
            return
        self.store.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.store.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.map, f)
        os.replace(tmp, self.store)
        self._dirty = False

    def reveal(self, placeholder: str) -> str | None:
        """Rückübersetzung (nur lokal): Platzhalter → Klartext."""
        for k, v in self.map.items():
            if v == placeholder:
                return k.split("|", 1)[1]
        return None

    # ---- Ersetzung ----
    def _value(self, kind: str, raw: str) -> str:
        v = raw.strip('"[]')
        if v.lower() in _KEEP or not v or v in self.map.values() or v.endswith(".example.invalid"):
            return raw
        ph = self._ph(kind, v)
        return raw.replace(v, ph) if v in raw else ph

    def line(self, text: str) -> str:
        t = text
        # 1. Bekannte Werte (Hostnamen/Benutzer aus Inventar und Ereignisfeldern)
        for value, kind in self.known:
            if len(value) >= 3 and value.lower() not in _KEEP:
                t = re.sub(r"(?<![\w-])" + re.escape(value) + r"(?![\w-])", lambda _m, v=value, k=kind: self._ph(k, v),
                           t, flags=re.IGNORECASE)
        t = _EMAIL.sub(lambda m: self._ph("USER", m.group(0).split("@")[0]) + "@example.invalid", t)
        t = _MAC.sub(lambda m: self._ph("MAC", m.group(0).replace("-", ":")), t)
        t = _IPV6.sub(lambda m: self._ph("IP6", m.group(0)) if m.group(0).count(":") >= 2 else m.group(0), t)
        t = _IPV4.sub(lambda m: self._ph("IP4", m.group(0)) if all(int(p) < 256 for p in m.group(0).split(".")) else m.group(0), t)  # noqa: E501
        t = _DOMAIN_USER.sub(lambda m: f"{self._ph('HOST', m.group(1))}\\{self._ph('USER', m.group(2))}", t)
        t = _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{self._value(_KEYS[m.group(1).lower()], m.group(3))}", t)
        for rx, kind, _grp in _PHRASE:
            t = rx.sub(lambda m, k=kind: m.group(1) + self._value(k, m.group(2)) + m.group(3), t)
        t = _SYSLOG_HOST.sub(lambda m: m.group(1) + self._value("HOST", m.group(2)) + m.group(3), t)
        t = _FQDN.sub(lambda m: self._ph("HOST", m.group(0)) + ".example.invalid", t)
        return t

    def lines(self, rows: list[str]) -> list[str]:
        out = [self.line(r) for r in rows]
        self.save()
        return out
