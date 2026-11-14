"""Active Response (Spec 4.8, R-06): FortiGate-IP-Sperre – manuell und optional automatisch.

Eine Sperre legt ein Adressobjekt ``siem-block-<ip>`` an und nimmt es in die Adressgruppe (Standard ``SIEM_BLOCK``) auf;
der Administrator verweist in der FortiGate auf diese Gruppe mit einer Deny-Regel. Schutzmechanismen: Schutzliste
(private Netze, Loopback und eigene Einträge sind nie sperrbar), Obergrenze gleichzeitiger Sperren, Ablaufzeit,
Rate-Limit für automatische Sperren, vollständiges Audit. Standard: aus.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import ssl
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import fortigate, sophos
from .security import crypto

CONTEXT = "fortigate.write_token"
GROUP_DEFAULT = "SIEM_BLOCK"
MAX_ACTIVE = 100
AUTO_PER_HOUR = 10
AUTO_RULES = ("win-bruteforce-ip", "linux-ssh-bruteforce", "fw-ips-high", "fw-portscan")
ALWAYS_PROTECTED = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                    "224.0.0.0/4", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10")


class ARError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def check_ip(value: str, protected: list[str]) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ARError("ar_invalid_ip") from exc
    if ip.version != 4:
        raise ARError("ar_ipv4_only")
    for net in (*ALWAYS_PROTECTED, *protected):
        try:
            if ip in ipaddress.ip_network(net, strict=False):
                raise ARError("ar_protected_ip")
        except ValueError:
            continue
    return str(ip)


class Store:
    def __init__(self, secrets_dir: Path, master_key: bytes) -> None:
        self.cfg_path = secrets_dir / "active-response.json"
        self.blocks_path = secrets_dir / "ar-blocks.json"
        self.key = master_key
        self.lock = threading.Lock()

    def config(self) -> dict[str, Any]:
        c = sophos._read(self.cfg_path)
        return {"enabled": bool(c.get("enabled")), "auto": bool(c.get("auto")), "group": c.get("group", GROUP_DEFAULT),
                "hours": int(c.get("hours", 24)), "protected": list(c.get("protected", [])),
                "has_token": bool(c.get("token"))}

    def token(self) -> str:
        blob = sophos._read(self.cfg_path).get("token")
        if not blob:
            raise ARError("ar_not_configured")
        try:
            return crypto.decrypt(self.key, base64.b64decode(blob), CONTEXT)
        except (crypto.DecryptionError, ValueError) as exc:
            raise ARError("ar_secret_unreadable") from exc

    def save(self, c: dict[str, Any], token: str | None) -> None:
        group = c["group"].strip() or GROUP_DEFAULT
        if not all(ch.isalnum() or ch in "_-" for ch in group) or len(group) > 35 or not 1 <= c["hours"] <= 720:
            raise ARError("ar_invalid_settings")
        prot = [p.strip() for p in c["protected"] if p.strip()]
        for p in prot:
            try:
                ipaddress.ip_network(p, strict=False)
            except ValueError as exc:
                raise ARError("ar_invalid_settings") from exc
        old = sophos._read(self.cfg_path)
        data = {"enabled": c["enabled"], "auto": bool(c["auto"] and c["enabled"]), "group": group, "hours": c["hours"],
                "protected": prot[:50], "token": old.get("token")}
        if token:
            data["token"] = base64.b64encode(crypto.encrypt(self.key, token, CONTEXT)).decode()
        sophos._write(self.cfg_path, data)

    def blocks(self) -> list[dict[str, Any]]:
        b = sophos._read(self.blocks_path).get("blocks", [])
        return b if isinstance(b, list) else []

    def save_blocks(self, blocks: list[dict[str, Any]], auto_log: list[float] | None = None) -> None:
        cur = sophos._read(self.blocks_path)
        sophos._write(self.blocks_path, {"blocks": blocks, "auto_log": auto_log if auto_log is not None else cur.get("auto_log", [])})

    def auto_log(self) -> list[float]:
        return [float(x) for x in sophos._read(self.blocks_path).get("auto_log", [])]


# ---------------------------------------------------------------- FortiGate-Aufrufe

def api_send(method: str, path: str, fcfg: dict[str, Any], token: str, body: dict[str, Any] | None = None,
             timeout: float = 20.0) -> tuple[int, Any]:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    pin = fcfg["tls_pin"]
    if pin:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(fcfg["host"], fcfg["port"], timeout=timeout, context=ctx)
    try:
        conn.connect()
        if pin and not hmac.compare_digest(hashlib.sha256(conn.sock.getpeercert(binary_form=True) or b"").hexdigest(), pin):  # type: ignore[union-attr]
            raise ARError("fortigate_pin_mismatch")
        conn.request(method, f"{path}?vdom={fcfg['vdom']}", body=json.dumps(body) if body is not None else None,
                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        resp = conn.getresponse()
        raw = resp.read(1_000_000)
        try:
            return resp.status, json.loads(raw) if raw else None
        except ValueError:
            return resp.status, None
    except ssl.SSLCertVerificationError as exc:
        raise ARError("fortigate_tls_untrusted") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise ARError("fortigate_unreachable") from exc
    finally:
        conn.close()


Sender = Callable[..., tuple[int, Any]]


def name_for(ip: str) -> str:
    return "siem-block-" + ip.replace(".", "_")


def fg_block(send: Sender, fcfg: dict[str, Any], token: str, ip: str, group: str, comment: str) -> None:
    n = name_for(ip)
    st, _ = send("POST", "/api/v2/cmdb/firewall/address", fcfg, token,
                 {"name": n, "type": "ipmask", "subnet": f"{ip} 255.255.255.255", "comment": comment[:250]})
    if st not in (200, 424) and st != 500:  # 500 mit „existiert bereits“ wird unten über die Gruppenaufnahme abgesichert
        raise ARError("ar_forti_rejected" if st in (400, 403, 401) else "ar_forti_error")
    st, _ = send("POST", f"/api/v2/cmdb/firewall/addrgrp/{group}/member", fcfg, token, {"name": n})
    if st == 404:
        raise ARError("ar_group_missing")
    if st not in (200, 500):
        raise ARError("ar_forti_rejected" if st in (400, 401, 403) else "ar_forti_error")


def fg_unblock(send: Sender, fcfg: dict[str, Any], token: str, ip: str, group: str) -> None:
    n = name_for(ip)
    send("DELETE", f"/api/v2/cmdb/firewall/addrgrp/{group}/member/{n}", fcfg, token)
    send("DELETE", f"/api/v2/cmdb/firewall/address/{n}", fcfg, token)


# ---------------------------------------------------------------- Logik

def block(store: Store, fstore: fortigate.Store, ip: str, hours: int | None, reason: str, by: str,
          send: Sender = api_send, now: datetime | None = None, auto: bool = False) -> dict[str, Any]:
    cfg = store.config()
    if not cfg["enabled"]:
        raise ARError("ar_disabled")
    ip = check_ip(ip, cfg["protected"])
    now = now or datetime.now(UTC)
    with store.lock:
        blocks = [b for b in store.blocks() if b["ip"] != ip]
        if len(blocks) >= MAX_ACTIVE:
            raise ARError("ar_limit_reached")
        log = [t for t in store.auto_log() if t > now.timestamp() - 3600]
        if auto:
            if len(log) >= AUTO_PER_HOUR:
                raise ARError("ar_auto_rate_limit")
            log.append(now.timestamp())
        h = max(1, min(hours or cfg["hours"], 720))
        fg_block(send, fstore.config(), store.token(), ip, cfg["group"], f"{reason} ({by})")
        entry = {"ip": ip, "reason": reason[:200], "by": by, "auto": auto,
                 "created": now.isoformat(timespec="seconds"), "until": (now + timedelta(hours=h)).isoformat(timespec="seconds")}
        store.save_blocks([*blocks, entry], log)
    return entry


def unblock(store: Store, fstore: fortigate.Store, ip: str, send: Sender = api_send) -> bool:
    cfg = store.config()
    with store.lock:
        blocks = store.blocks()
        if not any(b["ip"] == ip for b in blocks):
            return False
        fg_unblock(send, fstore.config(), store.token(), ip, cfg["group"])
        store.save_blocks([b for b in blocks if b["ip"] != ip])
    return True


def expire(store: Store, fstore: fortigate.Store, now: datetime | None = None, send: Sender = api_send) -> list[str]:
    now = now or datetime.now(UTC)
    gone = [b["ip"] for b in store.blocks() if datetime.fromisoformat(b["until"]) <= now]
    done = []
    for ip in gone:
        try:
            unblock(store, fstore, ip, send)
            done.append(ip)
        except ARError:
            continue  # nächster Versuch im nächsten Zyklus
    return done


def auto_candidate(alert: dict[str, Any]) -> str | None:
    """IP einer Alarmmeldung, die für eine automatische Sperre in Frage kommt (nur ausgewählte IP-bezogene Regeln)."""
    rule = alert.get("rule", {})
    if rule.get("id") in AUTO_RULES and rule.get("group_by") == "source.ip" and alert.get("severity") in ("high", "critical"):
        return str(alert.get("group") or "") or None
    return None


class Expirer(threading.Thread):
    def __init__(self, store: Store, fstore: fortigate.Store) -> None:
        super().__init__(daemon=True, name="ar-expirer")
        self.store, self.fstore = store, fstore
        self.stop = threading.Event()

    def run(self) -> None:
        while not self.stop.wait(60):
            if self.store.config()["enabled"] and self.store.blocks():
                expire(self.store, self.fstore)
