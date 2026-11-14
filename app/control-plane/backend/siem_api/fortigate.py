"""FortiGate-REST-API: ARP-Tabelle und DHCP-Leases je VLAN → Asset-Ereignisse (IP ↔ MAC ↔ Hostname).

Abruf alle 5 min mit API-Token (Bearer, nur lesend). Ereignisse entstehen bei neuer/geänderter Zuordnung und als
stündliche Auffrischung; wechselt eine IP die MAC, entsteht ``ip-mac-changed`` (Grundlage für den ARP-Spoofing-Alarm).
TLS: Prüfung gegen das Systemzertifikatsverzeichnis oder – für selbstsignierte Zertifikate – **Pinning** auf den
SHA-256-Fingerabdruck, den der Administrator im Web-UI bestätigt.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import sophos  # gemeinsame Hilfen: Datei-Ablage, Zustellung an Vector
from .security import crypto

INTERVAL_SECONDS = 300
REFRESH_SECONDS = 3600
CONTEXT = "fortigate.token"
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
_VDOM = re.compile(r"^[A-Za-z0-9_-]{1,31}$")
_PIN = re.compile(r"^([0-9a-fA-F]{2}:?){31}[0-9a-fA-F]{2}$")
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


class FortiError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def norm_pin(value: str) -> str:
    return value.replace(":", "").lower()


class Store:
    def __init__(self, secrets_dir: Path, master_key: bytes) -> None:
        self.cfg_path = secrets_dir / "fortigate.json"
        self.state_path = secrets_dir / "fortigate-state.json"
        self.key = master_key
        self.lock = threading.Lock()

    def config(self) -> dict[str, Any]:
        c = sophos._read(self.cfg_path)
        return {"enabled": bool(c.get("enabled")), "host": c.get("host", ""), "port": int(c.get("port", 443)),
                "vdom": c.get("vdom", "root"), "tls_pin": c.get("tls_pin", ""), "has_token": bool(c.get("token"))}

    def token(self) -> str:
        blob = sophos._read(self.cfg_path).get("token")
        if not blob:
            raise FortiError("fortigate_not_configured")
        try:
            return crypto.decrypt(self.key, base64.b64decode(blob), CONTEXT)
        except (crypto.DecryptionError, ValueError) as exc:
            raise FortiError("fortigate_secret_unreadable") from exc

    def save(self, *, enabled: bool, host: str, port: int, vdom: str, tls_pin: str, token: str | None) -> None:
        host, vdom, tls_pin = host.strip(), vdom.strip() or "root", norm_pin(tls_pin.strip())
        if host and not _HOST.match(host):
            raise FortiError("fortigate_invalid_host")
        if not 1 <= port <= 65535 or not _VDOM.match(vdom) or (tls_pin and not _PIN.match(tls_pin)):
            raise FortiError("fortigate_invalid_settings")
        old = sophos._read(self.cfg_path)
        data = {"enabled": enabled, "host": host, "port": port, "vdom": vdom, "tls_pin": tls_pin, "token": old.get("token")}
        if token:
            data["token"] = base64.b64encode(crypto.encrypt(self.key, token, CONTEXT)).decode()
        sophos._write(self.cfg_path, data)

    def state(self) -> dict[str, Any]:
        return sophos._read(self.state_path)

    def save_state(self, st: dict[str, Any]) -> None:
        sophos._write(self.state_path, st)


# ---------------------------------------------------------------- HTTP (TLS mit Pinning)

def fetch_fingerprint(host: str, port: int, timeout: float = 8.0) -> str:
    """SHA-256-Fingerabdruck des Serverzertifikats (ohne Prüfung; der Administrator bestätigt ihn)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True) or b"").hexdigest()
    except OSError as exc:
        raise FortiError("fortigate_unreachable") from exc


def api_get(host: str, port: int, path: str, token: str, pin: str, timeout: float = 20.0) -> Any:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if pin:  # Pinning ersetzt die Zertifikatskette (selbstsigniert)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    try:
        conn.connect()
        if pin:
            der = conn.sock.getpeercert(binary_form=True) or b""  # type: ignore[union-attr]
            if not hmac.compare_digest(hashlib.sha256(der).hexdigest(), pin):
                raise FortiError("fortigate_pin_mismatch")
        conn.request("GET", path, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        resp = conn.getresponse()
        body = resp.read(8_000_000)
        if resp.status in (401, 403):
            raise FortiError("fortigate_auth_failed")
        if resp.status != 200:
            raise FortiError(f"fortigate_http_{resp.status}" if resp.status in (404, 500, 503) else "fortigate_http_error")
        return json.loads(body)
    except ssl.SSLCertVerificationError as exc:
        raise FortiError("fortigate_tls_untrusted") from exc
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise FortiError("fortigate_unreachable") from exc
    finally:
        conn.close()


def fetch(cfg: dict[str, Any], token: str, get=api_get) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    q = f"?vdom={cfg['vdom']}"
    arp = get(cfg["host"], cfg["port"], "/api/v2/monitor/network/arp" + q, token, cfg["tls_pin"])
    try:
        dhcp = get(cfg["host"], cfg["port"], "/api/v2/monitor/system/dhcp" + q, token, cfg["tls_pin"])
    except FortiError as exc:  # DHCP-Server nicht aktiv / keine Berechtigung: ARP allein ist nutzbar
        if exc.code in ("fortigate_http_404", "fortigate_http_error", "fortigate_auth_failed"):
            dhcp = {"results": []}
        else:
            raise
    return list(arp.get("results") or []), list(dhcp.get("results") or [])


# ---------------------------------------------------------------- Normalisierung

def _mac(v: Any) -> str | None:
    m = str(v or "").strip().lower().replace("-", ":")
    return m if _MAC.match(m) and m != "00:00:00:00:00:00" else None


def _ip(v: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return None


def build_events(arp: list[dict[str, Any]], dhcp: list[dict[str, Any]], mem: dict[str, Any], now: datetime,
                 host: str) -> list[dict[str, Any]]:
    """Asset-Ereignisse aus ARP/DHCP; ``mem`` (mac→Zuordnung, ip→mac) wird fortgeschrieben."""
    ts = now.timestamp()
    macs: dict[str, dict[str, Any]] = mem.setdefault("macs", {})
    ips: dict[str, str] = mem.setdefault("ips", {})
    merged: dict[str, dict[str, Any]] = {}
    for row in dhcp:
        mac, ip = _mac(row.get("mac")), _ip(row.get("ip"))
        if mac and ip:
            merged[mac] = {"mac": mac, "ip": ip, "hostname": str(row.get("hostname") or "")[:63], "iface": str(row.get("interface") or ""),
                           "src": "dhcp"}
    for row in arp:
        mac, ip = _mac(row.get("mac")), _ip(row.get("ip"))
        if mac and ip:
            cur = merged.setdefault(mac, {"mac": mac, "ip": ip, "hostname": "", "iface": "", "src": "arp"})
            cur["iface"] = cur["iface"] or str(row.get("interface") or "")
    events = []
    for mac, e in merged.items():
        prev = macs.get(mac)
        old_mac_for_ip = ips.get(e["ip"])
        changed_ip_owner = old_mac_for_ip is not None and old_mac_for_ip != mac
        fresh = prev and prev["ip"] == e["ip"] and prev["hostname"] == e["hostname"] and ts - prev["ts"] < REFRESH_SECONDS
        if fresh and not changed_ip_owner:
            ips[e["ip"]] = mac
            continue
        action = "ip-mac-changed" if changed_ip_owner else "asset-seen"
        ev = {
            "@timestamp": now.isoformat().replace("+00:00", "Z"),
            "siem": {"collector": "fortigate-api", "pipeline": "fortigate-api", "category": "asset"},
            "event": {"kind": "event", "module": "fortigate", "dataset": f"fortigate.{e['src']}", "action": action,
                      "category": ["host", "network"], "type": ["info" if action == "asset-seen" else "change"]},
            "observer": {"vendor": "Fortinet", "product": "FortiGate", "type": "firewall", "name": host,
                         "ingress": {"interface": {"name": e["iface"]}} if e["iface"] else {}},
            "source": {"mac": mac, "ip": e["ip"]},
            "message": f"{e['ip']} ↔ {mac}" + (f" ({e['hostname']})" if e["hostname"] else ""),
        }
        if e["hostname"]:
            ev["host"] = {"hostname": e["hostname"]}
        if changed_ip_owner:
            ev["event"]["reason"] = f"IP war zuvor {old_mac_for_ip}"
            ev["log"] = {"level": "warning"}
        if not ev["observer"]["ingress"]:
            del ev["observer"]["ingress"]
        events.append(ev)
        macs[mac] = {"ip": e["ip"], "hostname": e["hostname"], "ts": ts}
        ips[e["ip"]] = mac
    return events


def run_cycle(store: Store, send=sophos.send_to_vector, get=api_get, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    cfg = store.config()
    st = store.state()
    result: dict[str, Any] = {"at": now.isoformat(), "error": None, "sent": 0, "arp": 0, "dhcp": 0}
    try:
        if not cfg["host"] or not cfg["has_token"]:
            raise FortiError("fortigate_not_configured")
        arp, dhcp = fetch(cfg, store.token(), get)
        result["arp"], result["dhcp"] = len(arp), len(dhcp)
        mem = copy.deepcopy(st.get("mem", {}))  # erst nach erfolgreicher Zustellung übernehmen
        events = build_events(arp, dhcp, mem, now, cfg["host"])
        try:
            send(events)
        except sophos.SophosError as exc:  # Zustellfehler: nichts als gesehen merken
            raise FortiError("fortigate_vector_unavailable") from exc
        result["sent"] = len(events)
        st["mem"] = mem
    except FortiError as exc:
        result["error"] = exc.code
    st["last_run"] = result
    store.save_state(st)
    return result


class Poller(threading.Thread):
    def __init__(self, store: Store) -> None:
        super().__init__(daemon=True, name="fortigate-poller")
        self.store = store
        self.stop = threading.Event()
        self.trigger = threading.Event()

    def run(self) -> None:
        while not self.stop.is_set():
            if self.store.config()["enabled"]:
                with self.store.lock:
                    run_cycle(self.store)
            self.trigger.wait(INTERVAL_SECONDS)
            self.trigger.clear()

