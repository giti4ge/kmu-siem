#!/usr/bin/env python3
"""siem-hostd – privilegierte Host-Schnittstelle der KMU-SIEM Appliance (ADR-0009).

Einzige Brücke zwischen Web-UI/API und dem Host. Führt ausschließlich eine feste
Liste geprüfter Aktionen aus (keine Shell, keine freien Befehle).

Betrieb:
  siem-hostd serve                       Dienst (systemd), Unix-Socket /run/siem/hostd.sock
  siem-hostd system status               Systemzustand (JSON)
  siem-hostd firewall show               Freigaben, ausstehende Änderung
  siem-hostd firewall apply --file F     Neue Freigaben aktivieren (Dead-Man's-Switch)
  siem-hostd firewall confirm TOKEN      Änderung bestätigen (dauerhaft übernehmen)
  siem-hostd firewall rollback           Ausstehende Änderung sofort zurücknehmen
  siem-hostd firewall init [--add-ssh-source IP …]   (Installer) Grundkonfiguration anwenden
  siem-hostd firewall render             nftables-Konfiguration ausgeben

Protokoll (Socket): eine JSON-Zeile je Anfrage/Antwort
  → {"action": "firewall.apply", "params": {...}, "actor": "admin@web"}
  ← {"ok": true, "result": {...}}  bzw.  {"ok": false, "error": "..."}

Nur Python-Standardbibliothek (läuft vor und unabhängig von den Containern).
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import logging
import os
import re
import secrets
import select
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:  # nur unter Unix verfügbar (Entwicklung unter Windows: Tests ohne Socket-Teil)
    import grp
except ImportError:  # pragma: no cover
    grp = None  # type: ignore[assignment]

# --------------------------------------------------------------------------- #
# Konfiguration (Pfade per Umgebung überschreibbar – für Tests)
# --------------------------------------------------------------------------- #
SIEM_ROOT = Path(os.environ.get("SIEM_ROOT", "/opt/siem"))
SOCKET_PATH = Path(os.environ.get("SIEM_HOSTD_SOCKET", "/run/siem/hostd.sock"))
DATA_DIR = Path(os.environ.get("SIEM_HOSTD_DATA", str(SIEM_ROOT / "data" / "hostd")))
NFT_CONF = Path(os.environ.get("SIEM_NFT_CONF", "/etc/nftables.conf"))
INSTALL_STATE = Path(os.environ.get("SIEM_INSTALL_STATE", "/var/lib/siem/install.state"))
AUDIT_LOG = Path(os.environ.get("SIEM_HOSTD_AUDIT", "/var/log/siem-hostd.log"))
SOCKET_GROUP = os.environ.get("SIEM_HOSTD_GROUP", "siem-hostd")
CONFIRM_TIMEOUT = int(os.environ.get("SIEM_FW_CONFIRM_TIMEOUT", "60"))

MAX_MESSAGE = 64 * 1024
MAX_SOURCES = 256
BRIDGE = "br-siem"

# Dienste und Ports: fest im Code (Allowlist). Reihenfolge = Reihenfolge der Regeln.
# (Protokoll, externer Port, interner Port). Weicht der interne Port ab, wird per
# nftables umgeleitet (REDIRECT); so laufen Proxy und Vector ohne Root-Rechte auf
# Ports > 1024. Der interne Port ist nur für umgeleiteten Verkehr erreichbar.
SERVICES: dict[str, list[tuple[str, int, int]]] = {
    "ssh": [("tcp", 22, 22)],
    "https": [("tcp", 443, 8443)],
    "syslog": [("udp", 514, 10514), ("tcp", 514, 10514)],
    "syslog_tls": [("tcp", 6514, 6514)],
    "wef": [("tcp", 5985, 5985)],
    "wef_https": [("tcp", 5986, 5986)],
    "snmptrap": [("udp", 162, 10162)],
}
RATE_LIMITS = {
    "ssh": "ct state new limit rate 30/minute burst 20 packets",
    "https": "ct state new limit rate 600/minute burst 200 packets",
}
# Eingangsschutz je Quelladresse (nur Quellen der Allowlist erreichen diese Regeln):
# UDP: Pakete pro Sekunde; TCP: neue Verbindungen pro Minute (gleichzeitige Verbindungen begrenzt Vector).
# Überschreitungen werden verworfen und gezählt (nftables-Zähler), das übrige System bleibt bedienbar.
UDP_PER_SOURCE_PPS = {"syslog": 2000, "snmptrap": 200}
TCP_NEW_PER_MINUTE = {"syslog": 100, "syslog_tls": 100, "wef": 120, "wef_https": 120}
SNMP_MAX_UDP = 8200  # UDP-Länge inkl. Kopf; SNMP-Traps sind klein
DEFAULT_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
DEFAULT_V6 = ["fc00::/7", "fe80::/10"]
DEFAULT_SOURCES: dict[str, list[str]] = {
    "ssh": DEFAULT_V4 + DEFAULT_V6,
    "https": DEFAULT_V4 + DEFAULT_V6,
    "syslog": DEFAULT_V4,
    "syslog_tls": DEFAULT_V4,
    "wef": DEFAULT_V4,
    "wef_https": [],
    "snmptrap": DEFAULT_V4,
}

log = logging.getLogger("siem-hostd")


class HostdError(Exception):
    """Fachlicher Fehler, der dem Aufrufer gemeldet wird."""


# --------------------------------------------------------------------------- #
# Hilfsfunktionen
# --------------------------------------------------------------------------- #
def atomic_write(path: Path, data: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".siem-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def audit(action: str, actor: str, ok: bool, detail: str = "", uid: int | None = None) -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "actor": actor or "-",
        "uid": uid,
        "ok": ok,
        "detail": detail,
    }
    log.info("audit %s", json.dumps(entry, ensure_ascii=False))
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:  # Protokollfehler dürfen die Aktion nicht verhindern
        log.warning("Audit-Log nicht schreibbar: %s", exc)


def run_nft(args: list[str], stdin: str | None = None) -> None:
    """nft ausführen; Fehler als HostdError."""
    proc = subprocess.run(  # noqa: S603 – feste Argumentliste, keine Shell
        ["/usr/sbin/nft", *args], input=stdin, text=True, capture_output=True, timeout=30, check=False
    )
    if proc.returncode != 0:
        raise HostdError(f"nft {' '.join(args)} fehlgeschlagen: {proc.stderr.strip()[:500]}")


# --------------------------------------------------------------------------- #
# Firewall: Validierung und Erzeugung der nftables-Konfiguration
# --------------------------------------------------------------------------- #
def normalize_sources(values: Any) -> list[str]:
    if not isinstance(values, list):
        raise HostdError("Quellen müssen eine Liste sein")
    if len(values) > MAX_SOURCES:
        raise HostdError(f"Zu viele Quellen (maximal {MAX_SOURCES})")
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in values:
        if not isinstance(value, str) or not value.strip() or len(value) > 64:
            raise HostdError(f"Ungültige Quelle: {value!r}")
        try:
            nets.append(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as exc:
            raise HostdError(f"Ungültige Adresse oder ungültiges Netz: {value!r}") from exc
    v4 = list(ipaddress.collapse_addresses(n for n in nets if n.version == 4))
    v6 = list(ipaddress.collapse_addresses(n for n in nets if n.version == 6))
    return [str(n) for n in v4] + [str(n) for n in v6]


def validate_config(cfg: Any) -> dict[str, Any]:
    """Prüft und normalisiert eine Firewall-Konfiguration."""
    if not isinstance(cfg, dict):
        raise HostdError("Konfiguration muss ein Objekt sein")
    services = cfg.get("services")
    if not isinstance(services, dict):
        raise HostdError("'services' fehlt oder ist kein Objekt")
    unknown = sorted(set(services) - set(SERVICES))
    if unknown:
        raise HostdError(f"Unbekannte Dienste: {', '.join(unknown)}")
    result: dict[str, list[str]] = {}
    for name in SERVICES:
        entry = services.get(name, {"sources": []})
        if not isinstance(entry, dict) or set(entry) - {"sources"}:
            raise HostdError(f"Dienst {name}: nur 'sources' erlaubt")
        result[name] = normalize_sources(entry.get("sources", []))
    return {"version": 1, "services": {n: {"sources": s} for n, s in result.items()}}


def default_config() -> dict[str, Any]:
    return validate_config({"services": {n: {"sources": s} for n, s in DEFAULT_SOURCES.items()}})


def _elements(sources: list[str]) -> str:
    return f"; elements = {{ {', '.join(sources)} }}" if sources else ""


def render_nft(cfg: dict[str, Any]) -> str:
    """Erzeugt die vollständige nftables-Konfiguration (deterministisch)."""
    lines = [
        "#!/usr/sbin/nft -f",
        "# Von siem-hostd verwaltet – KMU-SIEM Appliance-Firewall. Nicht manuell bearbeiten.",
        "# Nur die Tabelle \"inet siem\" wird ersetzt; Tabellen von Docker bleiben unberührt.",
        "",
        "table inet siem",
        "delete table inet siem",
        "",
        "table inet siem {",
    ]
    for name in SERVICES:
        sources = cfg["services"][name]["sources"]
        v4 = [s for s in sources if ":" not in s]
        v6 = [s for s in sources if ":" in s]
        lines.append(f"    set allow_{name} {{ type ipv4_addr; flags interval; auto-merge{_elements(v4)}; }}")
        lines.append(f"    set allow_{name}6 {{ type ipv6_addr; flags interval; auto-merge{_elements(v6)}; }}")
    for name in sorted({*UDP_PER_SOURCE_PPS, *TCP_NEW_PER_MINUTE}):
        for fam, typ in (("4", "ipv4_addr"), ("6", "ipv6_addr")):
            lines.append(f"    set flood_{name}{fam} {{ type {typ}; flags dynamic; size 65535; timeout 1m; }}")
    lines += [
        "",
        "    chain input {",
        "        type filter hook input priority filter; policy drop;",
        "",
        '        iif "lo" accept',
        "        ct state established,related accept",
        "        ct state invalid drop",
        "",
        "        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded }"
        " limit rate 20/second accept",
        "        ip6 nexthdr icmpv6 icmpv6 type { echo-request, destination-unreachable, packet-too-big,"
        " time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept",
        "        udp sport 67 udp dport 68 accept",
        "",
    ]
    for name, ports in SERVICES.items():
        limit = f" {RATE_LIMITS[name]}" if name in RATE_LIMITS else ""
        for proto, ext, internal in ports:
            # Umgeleitete Dienste: nur Verkehr, der über den externen Port kam (ct status dnat)
            match = f"{proto} dport {internal}" + (" ct status dnat" if ext != internal else "")
            if name == "snmptrap":
                lines.append(f"        {match} udp length > {SNMP_MAX_UDP} counter drop")
            for fam, ip in (("4", "ip"), ("6", "ip6")):
                if proto == "udp" and name in UDP_PER_SOURCE_PPS:
                    pps = UDP_PER_SOURCE_PPS[name]
                    src = f"{ip} saddr @allow_{name}{'' if fam == '4' else '6'}"
                    lines.append(f"        {match} {src} add @flood_{name}{fam}"
                                 f" {{ {ip} saddr limit rate over {pps}/second burst {pps * 2} packets }} counter drop")
                elif proto == "tcp" and name in TCP_NEW_PER_MINUTE:
                    rate = TCP_NEW_PER_MINUTE[name]
                    src = f"{ip} saddr @allow_{name}{'' if fam == '4' else '6'}"
                    lines.append(f"        {match} ct state new {src} add @flood_{name}{fam}"
                                 f" {{ {ip} saddr limit rate over {rate}/minute burst {rate} packets }} counter drop")
            lines.append(f"        {match} ip saddr @allow_{name}{limit} accept")
            lines.append(f"        {match} ip6 saddr @allow_{name}6{limit} accept")
    lines += [
        "",
        '        limit rate 10/minute log prefix "siem-fw-drop: " level info',
        "    }",
        "",
        "    chain prerouting {",
        "        type nat hook prerouting priority dstnat; policy accept;",
    ]
    for _name, ports in SERVICES.items():
        for proto, ext, internal in ports:
            if ext != internal:
                lines.append(f"        {proto} dport {ext} redirect to :{internal}")
    lines += [
        "    }",
        "",
        "    chain forward {",
        "        type filter hook forward priority filter; policy drop;",
        "        ct state established,related accept",
        f'        iifname "{BRIDGE}" oifname != "{BRIDGE}" accept',
        "    }",
        "",
        "    chain output {",
        "        type filter hook output priority filter; policy accept;",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Firewall-Verwaltung mit Dead-Man's-Switch
# --------------------------------------------------------------------------- #
class FirewallManager:
    def __init__(
        self,
        data_dir: Path = DATA_DIR,
        nft_conf: Path = NFT_CONF,
        nft: Callable[[list[str], str | None], None] = run_nft,
        timeout: int = CONFIRM_TIMEOUT,
    ) -> None:
        self.committed_path = data_dir / "firewall.json"
        self.pending_path = data_dir / "firewall.pending.json"
        self.nft_conf = nft_conf
        self.nft = nft
        self.timeout = timeout
        self._lock = threading.RLock()
        self._timer: threading.Timer | None = None

    # --- Zustand ---------------------------------------------------------------
    def committed(self) -> dict[str, Any]:
        if self.committed_path.exists():
            return validate_config(json.loads(self.committed_path.read_text(encoding="utf-8")))
        return default_config()

    def pending(self) -> dict[str, Any] | None:
        if not self.pending_path.exists():
            return None
        return json.loads(self.pending_path.read_text(encoding="utf-8"))

    def show(self) -> dict[str, Any]:
        with self._lock:
            pend = self.pending()
            info = None
            if pend:
                info = {
                    "config": pend["config"],
                    "actor": pend.get("actor"),
                    "seconds_left": max(0, int(pend["deadline"] - time.time())),
                }
            return {"committed": self.committed(), "pending": info, "timeout": self.timeout}

    # --- Anwenden ---------------------------------------------------------------
    def _load(self, cfg: dict[str, Any]) -> None:
        text = render_nft(cfg)
        self.nft(["-c", "-f", "-"], text)
        self.nft(["-f", "-"], text)

    def _commit(self, cfg: dict[str, Any]) -> None:
        atomic_write(self.committed_path, json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", 0o600)
        atomic_write(self.nft_conf, render_nft(cfg), 0o600)

    def apply(self, cfg: Any, actor: str = "", timeout: int | None = None) -> dict[str, Any]:
        timeout = self.timeout if timeout is None else timeout
        if not 10 <= timeout <= 600:
            raise HostdError("Bestätigungsfrist muss zwischen 10 und 600 Sekunden liegen")
        new = validate_config(cfg)
        with self._lock:
            if self.pending():
                raise HostdError("Es gibt bereits eine unbestätigte Änderung – erst bestätigen oder zurücknehmen")
            previous = self.committed()
            self._load(new)  # prüft (nft -c) und aktiviert
            token = secrets.token_urlsafe(24)
            deadline = time.time() + timeout
            atomic_write(
                self.pending_path,
                json.dumps({"config": new, "previous": previous, "token": token,
                            "deadline": deadline, "actor": actor}, ensure_ascii=False),
                0o600,
            )
            self._schedule(timeout)
        audit("firewall.apply", actor, True, f"Bestätigung innerhalb {timeout}s erforderlich")
        return {"token": token, "timeout": timeout, "deadline": int(deadline)}

    def confirm(self, token: Any, actor: str = "") -> dict[str, Any]:
        if not isinstance(token, str) or not token:
            raise HostdError("Token fehlt")
        with self._lock:
            pend = self.pending()
            if not pend:
                raise HostdError("Keine unbestätigte Änderung vorhanden (evtl. bereits zurückgesetzt)")
            if not secrets.compare_digest(token, pend["token"]):
                audit("firewall.confirm", actor, False, "falsches Token")
                raise HostdError("Token ungültig")
            self._cancel_timer()
            self._commit(pend["config"])
            self.pending_path.unlink(missing_ok=True)
        audit("firewall.confirm", actor, True)
        return {"committed": True}

    def rollback(self, actor: str = "", reason: str = "manuell") -> dict[str, Any]:
        with self._lock:
            pend = self.pending()
            if not pend:
                return {"rolled_back": False}
            self._cancel_timer()
            try:
                self._load(validate_config(pend["previous"]))
            finally:
                self.pending_path.unlink(missing_ok=True)
        audit("firewall.rollback", actor, True, reason)
        return {"rolled_back": True}

    def apply_permanent(self, cfg: Any, actor: str = "installer") -> dict[str, Any]:
        """Ohne Dead-Man's-Switch – nur für den Installer (lokal, root)."""
        new = validate_config(cfg)
        with self._lock:
            if self.pending():
                raise HostdError("Es gibt eine unbestätigte Änderung")
            self._load(new)
            self._commit(new)
        audit("firewall.init", actor, True)
        return {"committed": True}

    def init(self, add_ssh_sources: list[str], actor: str = "installer") -> dict[str, Any]:
        cfg = self.committed()
        ssh = cfg["services"]["ssh"]["sources"] + list(add_ssh_sources)
        cfg["services"]["ssh"]["sources"] = ssh
        return self.apply_permanent(cfg, actor)

    # --- Timer --------------------------------------------------------------------
    def _schedule(self, seconds: float) -> None:
        self._cancel_timer()
        self._timer = threading.Timer(max(0.0, seconds), self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _cancel_timer(self) -> None:
        if self._timer:
            self._timer.cancel()
            self._timer = None

    def _expire(self) -> None:
        try:
            self.rollback(actor="siem-hostd", reason="Bestätigungsfrist abgelaufen (Dead-Man's-Switch)")
        except Exception:  # noqa: BLE001 – Timer darf nie stillschweigend sterben
            log.exception("Automatisches Zurücksetzen fehlgeschlagen")

    def resume(self) -> None:
        """Nach (Neu-)Start: offene Änderung zurücksetzen oder Restfrist planen."""
        pend = self.pending()
        if not pend:
            return
        remaining = pend["deadline"] - time.time()
        if remaining <= 0:
            self.rollback(actor="siem-hostd", reason="Frist während Neustart abgelaufen")
        else:
            log.info("Unbestätigte Firewall-Änderung – Rücknahme in %.0f s", remaining)
            self._schedule(remaining)


# --------------------------------------------------------------------------- #
# Systemzustand
# --------------------------------------------------------------------------- #
WATCHED_UNITS = ["docker", "nftables", "chrony", "auditd", "ssh", "siem-hostd"]


def _unit_state(unit: str) -> str:
    try:
        proc = subprocess.run(  # noqa: S603
            ["/usr/bin/systemctl", "is-active", unit], capture_output=True, text=True, timeout=5, check=False
        )
        return proc.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def _meminfo() -> dict[str, int]:
    info: dict[str, int] = {}
    with contextlib.suppress(OSError):
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            if key in ("MemTotal", "MemAvailable"):
                info[key] = int(rest.split()[0]) * 1024
    return info


def _disk(path: Path) -> dict[str, int] | None:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    return {"total": usage.total, "used": usage.used, "free": usage.free,
            "percent": round(usage.used * 100 / usage.total) if usage.total else 0}


def _install_state() -> dict[str, str]:
    steps: dict[str, str] = {}
    with contextlib.suppress(OSError):
        for line in INSTALL_STATE.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                steps[parts[0]] = parts[1]
    return steps


def _time_synced() -> bool | None:
    try:
        proc = subprocess.run(  # noqa: S603
            ["/usr/bin/timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return proc.stdout.strip() == "yes"
    except (OSError, subprocess.TimeoutExpired):
        return None


def system_status(fw: FirewallManager) -> dict[str, Any]:
    uptime = 0.0
    with contextlib.suppress(OSError, ValueError):
        uptime = float(Path("/proc/uptime").read_text().split()[0])
    version = "unknown"
    with contextlib.suppress(OSError):
        version = (SIEM_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    pend = fw.show()["pending"]
    return {
        "version": version,
        "hostname": socket.getfqdn(),
        "uptime_seconds": int(uptime),
        "load": list(os.getloadavg()),
        "memory": _meminfo(),
        "disk": {"system": _disk(Path("/")), "data": _disk(SIEM_ROOT / "data")},
        "services": {u: _unit_state(u) for u in WATCHED_UNITS},
        "time_synchronized": _time_synced(),
        "reboot_required": Path("/run/reboot-required").exists(),
        "firewall_pending": pend is not None,
        "install": _install_state(),
    }


# --------------------------------------------------------------------------- #
# System-Protokoll (nur lesen, feste Quellen)
# --------------------------------------------------------------------------- #
# Quelle → (Art, Ziel). Keine freien Pfade/Units/Container – nur diese Allowlist.
LOG_SOURCES: dict[str, tuple[str, str]] = {
    "install": ("file", "/var/log/siem-install.log"),
    "hostd-audit": ("file", "/var/log/siem-hostd.log"),
    "siem-hostd": ("journal", "siem-hostd"),
    "docker": ("journal", "docker"),
    "nftables": ("journal", "nftables"),
    "ssh": ("journal", "ssh"),
    "chrony": ("journal", "chrony"),
    "unattended-upgrades": ("file", "/var/log/unattended-upgrades/unattended-upgrades.log"),
    "opensearch": ("container", "siem-opensearch"),
    "vector": ("container", "siem-vector"),
    "proxy": ("container", "siem-proxy"),
    "api": ("container", "siem-api"),
    "dashboards": ("container", "siem-dashboards"),
}
LOG_MAX_LINES = 2000
LOG_SCAN_LINES = 20000  # Vorrat für die Filterung
LOG_FILE_TAIL_BYTES = 4 * 1024 * 1024


def _run_lines(cmd: list[str]) -> list[str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HostdError(f"Protokoll nicht lesbar: {exc}") from exc
    # docker logs schreibt die Container-Ausgabe teils auf stderr
    return (proc.stdout + proc.stderr).splitlines()


def _tail_file(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - LOG_FILE_TAIL_BYTES))
        data = fh.read().decode("utf-8", errors="replace")
    lines = data.splitlines()
    return lines[1:] if size > LOG_FILE_TAIL_BYTES else lines


def system_logs(params: dict[str, Any], reader: Callable[[list[str]], list[str]] = _run_lines) -> dict[str, Any]:
    source = params.get("source")
    if source not in LOG_SOURCES:
        raise HostdError("Unbekannte Protokollquelle")
    lines = params.get("lines", 500)
    if not isinstance(lines, int) or isinstance(lines, bool) or not 1 <= lines <= LOG_MAX_LINES:
        raise HostdError(f"lines muss zwischen 1 und {LOG_MAX_LINES} liegen")
    query = params.get("query") or ""
    if not isinstance(query, str) or len(query) > 100:
        raise HostdError("Filter ungültig (höchstens 100 Zeichen)")
    kind, target = LOG_SOURCES[source]
    if kind == "file":
        raw = _tail_file(target)
    elif kind == "journal":
        raw = reader(["/usr/bin/journalctl", "-u", target, "-n", str(LOG_SCAN_LINES), "--no-pager", "-o", "short-iso"])
    else:
        raw = reader(["/usr/bin/docker", "logs", "--tail", str(LOG_SCAN_LINES), "--timestamps", target])
    if query:
        q = query.lower()
        raw = [ln for ln in raw if q in ln.lower()]
    return {"source": source, "lines": [ln[:4000] for ln in raw[-lines:]], "truncated": len(raw) > lines}


# --------------------------------------------------------------------------- #
# Aktionen (Allowlist)
# --------------------------------------------------------------------------- #
def vector_reload() -> dict[str, Any]:
    """Vector per SIGHUP neu laden (Geräteliste/Parser), ohne Neustart und ohne Ereignisverlust."""
    try:
        proc = subprocess.run(  # noqa: S603
            ["/usr/bin/docker", "kill", "--signal", "HUP", "siem-vector"],
            capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HostdError(f"Vector nicht erreichbar: {exc}") from exc
    if proc.returncode != 0:
        raise HostdError("Vector konnte nicht neu geladen werden")
    return {"reloaded": True}


SUPPORT_DIR = Path(os.environ.get("SIEM_SUPPORT_DIR", str(DATA_DIR / "support")))
SUPPORT_MAX_HOURS = 72
_SSH_KEY = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh\.com) "
                      r"[A-Za-z0-9+/=]{40,2000}(?: [A-Za-z0-9@._:-]{1,64})?$")


class SupportAccess:
    """Zeitlich begrenzter SSH-Zugang für den Dienstleister (Benutzer siem-support, nur Allowlist-Befehle).

    sshd liest die Schlüssel für diesen Benutzer ausschließlich aus ``support/authorized_keys`` (siehe SSH-Härtung);
    ohne Eintrag ist der Zugang gesperrt. Ablauf wird per Timer und nach einem Neustart des Dienstes durchgesetzt.
    """

    def __init__(self, directory: Path = SUPPORT_DIR) -> None:
        self.dir = directory
        self.keys = directory / "authorized_keys"
        self.state = directory / "state.json"
        self.timer: threading.Timer | None = None
        self.lock = threading.Lock()

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state.read_text("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def status(self) -> dict[str, Any]:
        st = self._read()
        until = float(st.get("until", 0))
        active = until > time.time() and self.keys.exists() and self.keys.stat().st_size > 0
        return {"active": active, "until": until if active else None, "from": st.get("from") if active else None,
                "by": st.get("by") if active else None, "max_hours": SUPPORT_MAX_HOURS}

    def enable(self, params: dict[str, Any], actor: str) -> dict[str, Any]:
        key = str(params.get("key", "")).strip()
        hours = params.get("hours", 4)
        source = str(params.get("source", "")).strip()
        if not _SSH_KEY.match(key):
            raise HostdError("Öffentlicher SSH-Schlüssel ungültig (eine Zeile, ed25519/ecdsa/rsa)")
        if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= SUPPORT_MAX_HOURS:
            raise HostdError(f"Dauer muss zwischen 1 und {SUPPORT_MAX_HOURS} Stunden liegen")
        try:
            net = ipaddress.ip_network(source, strict=False)
        except ValueError as exc:
            raise HostdError("Quelladresse (IP oder Netz) erforderlich") from exc
        if net.prefixlen == 0 or (net.version == 4 and net.prefixlen < 16):
            raise HostdError("Quellnetz zu groß (mindestens /16)")
        until = time.time() + hours * 3600
        with self.lock:
            self.dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.dir, 0o700)
            line = f'restrict,from="{net}" {key}\n'
            atomic_write(self.keys, line, 0o600)
            atomic_write(self.state, json.dumps({"until": until, "from": str(net), "by": actor}), 0o600)
            self._arm(hours * 3600)
        audit("support.enable", actor, True, f"{net} {hours}h")
        return self.status()

    def disable(self, actor: str = "system", reason: str = "manuell") -> dict[str, Any]:
        with self.lock:
            if self.timer:
                self.timer.cancel()
                self.timer = None
            atomic_write(self.keys, "", 0o600)
            atomic_write(self.state, json.dumps({"until": 0}), 0o600)
        audit("support.disable", actor, True, reason)
        return self.status()

    def _arm(self, seconds: float) -> None:
        if self.timer:
            self.timer.cancel()
        self.timer = threading.Timer(seconds, self._expire)
        self.timer.daemon = True
        self.timer.start()

    def _expire(self) -> None:
        self.disable("system", "abgelaufen")

    def resume(self) -> None:
        """Nach Dienststart: abgelaufenen Zugang sperren, laufenden weiter begrenzen."""
        st = self._read()
        until = float(st.get("until", 0))
        if self.keys.exists() and self.keys.stat().st_size > 0:
            if until <= time.time():
                self.disable("system", "abgelaufen (Neustart)")
            else:
                with self.lock:
                    self._arm(until - time.time())


class Dispatcher:
    def __init__(self, fw: FirewallManager, status: Callable[[], dict[str, Any]] | None = None,
                 support: SupportAccess | None = None) -> None:
        self.fw = fw
        self.support = support or SupportAccess()
        self.status = status or (lambda: system_status(fw))
        self.actions: dict[str, Callable[[dict[str, Any], str], Any]] = {
            "system.status": lambda p, a: self.status(),
            "system.logs": lambda p, a: system_logs(p),
            "vector.reload": lambda p, a: vector_reload(),
            "support.status": lambda p, a: self.support.status(),
            "support.enable": lambda p, a: self.support.enable(p, a),
            "support.disable": lambda p, a: self.support.disable(a),
            "firewall.show": lambda p, a: self.fw.show(),
            "firewall.apply": lambda p, a: self.fw.apply(p.get("config"), a, p.get("timeout")),
            "firewall.confirm": lambda p, a: self.fw.confirm(p.get("token"), a),
            "firewall.rollback": lambda p, a: self.fw.rollback(a),
        }

    def handle(self, request: Any, uid: int | None = None) -> dict[str, Any]:
        if not isinstance(request, dict):
            return {"ok": False, "error": "Anfrage muss ein JSON-Objekt sein"}
        action = request.get("action")
        params = request.get("params", {})
        actor = request.get("actor", "")
        if not isinstance(actor, str) or len(actor) > 128:
            return {"ok": False, "error": "Ungültiger Akteur"}
        if action not in self.actions:
            audit(str(action)[:64], actor, False, "unbekannte Aktion", uid)
            return {"ok": False, "error": f"Unbekannte Aktion: {str(action)[:64]}"}
        if not isinstance(params, dict):
            return {"ok": False, "error": "'params' muss ein Objekt sein"}
        try:
            return {"ok": True, "result": self.actions[action](params, actor)}
        except HostdError as exc:
            audit(action, actor, False, str(exc), uid)
            return {"ok": False, "error": str(exc)}
        except Exception:  # noqa: BLE001
            log.exception("Fehler bei %s", action)
            audit(action, actor, False, "interner Fehler", uid)
            return {"ok": False, "error": "Interner Fehler (siehe Journal von siem-hostd)"}


# --------------------------------------------------------------------------- #
# Socket-Server
# --------------------------------------------------------------------------- #
def peer_uid(sock: socket.socket) -> int | None:
    with contextlib.suppress(OSError, AttributeError):
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        return uid
    return None


class _Handler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self) -> None:
        dispatcher: Dispatcher = self.server.dispatcher  # type: ignore[attr-defined]
        line = self.rfile.readline(MAX_MESSAGE + 1)
        if len(line) > MAX_MESSAGE:
            response = {"ok": False, "error": "Anfrage zu groß"}
        else:
            try:
                request = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                response = {"ok": False, "error": "Ungültiges JSON"}
            else:
                response = dispatcher.handle(request, peer_uid(self.connection))
        self.wfile.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))


# UnixStreamServer fehlt unter Windows (nur Entwicklung); auf dem Host immer vorhanden.
_UnixServerBase: Any = getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)


class HostdServer(socketserver.ThreadingMixIn, _UnixServerBase):
    daemon_threads = True

    def __init__(self, path: Path, dispatcher: Dispatcher) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        old_umask = os.umask(0o117)
        try:
            super().__init__(str(path), _Handler)
        finally:
            os.umask(old_umask)
        try:
            if grp is None:
                raise KeyError(SOCKET_GROUP)
            gid = grp.getgrnam(SOCKET_GROUP).gr_gid
            os.chown(path, 0, gid)
            os.chmod(path, 0o660)
        except (KeyError, PermissionError):
            os.chmod(path, 0o600)
        self.dispatcher = dispatcher


def serve() -> int:
    fw = FirewallManager()
    fw.resume()
    support = SupportAccess()
    support.resume()
    server = HostdServer(SOCKET_PATH, Dispatcher(fw, support=support))
    log.info("siem-hostd bereit auf %s", SOCKET_PATH)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


# --------------------------------------------------------------------------- #
# Kommandozeile
# --------------------------------------------------------------------------- #
def call(action: str, params: dict[str, Any] | None = None, actor: str = "") -> dict[str, Any]:
    actor = actor or f"cli:{os.environ.get('SUDO_USER') or os.environ.get('USER', 'root')}"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(60)
        sock.connect(str(SOCKET_PATH))
        sock.sendall((json.dumps({"action": action, "params": params or {}, "actor": actor}) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode("utf-8"))


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def _result(resp: dict[str, Any]) -> Any:
    if not resp.get("ok"):
        print(f"Fehler: {resp.get('error')}", file=sys.stderr)
        sys.exit(2)
    return resp["result"]


def _ask_confirm(seconds: int) -> bool:
    print(f"Neue Firewall-Regeln sind aktiv. Ist die Verbindung weiterhin in Ordnung?\n"
          f"Bestätigen mit 'j' innerhalb von {seconds} s – sonst automatische Rücknahme: ", end="", flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], seconds - 2)
    if not ready:
        print()
        return False
    return sys.stdin.readline().strip().lower() in ("j", "ja", "y", "yes")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(prog="siem-hostd", description="Privilegierte Host-Schnittstelle")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="Dienst starten")

    p_sys = sub.add_parser("system", help="System")
    p_sys.add_argument("what", choices=["status", "logs"])
    p_sys.add_argument("--source", choices=sorted(LOG_SOURCES), default="install")
    p_sys.add_argument("--lines", type=int, default=100)
    p_sys.add_argument("--query", default="")

    p_fw = sub.add_parser("firewall", help="Firewall")
    fw_sub = p_fw.add_subparsers(dest="fwcmd", required=True)
    fw_sub.add_parser("show")
    p_apply = fw_sub.add_parser("apply")
    p_apply.add_argument("--file", required=True, help="JSON mit {\"services\": {…}}")
    p_apply.add_argument("--timeout", type=int, default=None)
    p_apply.add_argument("--no-wait", action="store_true", help="nicht interaktiv nachfragen, Token ausgeben")
    p_conf = fw_sub.add_parser("confirm")
    p_conf.add_argument("token")
    fw_sub.add_parser("rollback")
    p_init = fw_sub.add_parser("init", help="(Installer) Grundkonfiguration dauerhaft anwenden")
    p_init.add_argument("--add-ssh-source", action="append", default=[])
    fw_sub.add_parser("render", help="nftables-Konfiguration der gespeicherten Freigaben ausgeben")

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        return serve()

    if args.cmd == "system":
        if args.what == "logs":
            res = _result(call("system.logs", {"source": args.source, "lines": args.lines, "query": args.query}))
            print("\n".join(res["lines"]))
            return 0
        _print(_result(call("system.status")))
        return 0

    # Firewall
    if args.fwcmd == "init":
        try:
            _print(FirewallManager().init(args.add_ssh_source))
        except HostdError as exc:
            print(f"Fehler: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.fwcmd == "render":
        print(render_nft(FirewallManager().committed()), end="")
        return 0
    if args.fwcmd == "show":
        _print(_result(call("firewall.show")))
        return 0
    if args.fwcmd == "confirm":
        _print(_result(call("firewall.confirm", {"token": args.token})))
        return 0
    if args.fwcmd == "rollback":
        _print(_result(call("firewall.rollback")))
        return 0
    if args.fwcmd == "apply":
        try:
            cfg = json.loads(Path(args.file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Fehler: Datei nicht lesbar: {exc}", file=sys.stderr)
            return 2
        params: dict[str, Any] = {"config": cfg}
        if args.timeout is not None:
            params["timeout"] = args.timeout
        res = _result(call("firewall.apply", params))
        if args.no_wait or not sys.stdin.isatty():
            _print(res)
            return 0
        if _ask_confirm(res["timeout"]):
            _print(_result(call("firewall.confirm", {"token": res["token"]})))
            return 0
        _print(_result(call("firewall.rollback")))
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
