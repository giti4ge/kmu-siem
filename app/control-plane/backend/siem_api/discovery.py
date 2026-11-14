"""Discovery-Scanner (Spec 4.6): findet Geräte in einem internen Netz und schlägt Logquellen vor.

Bewusst zurückhaltend: nur private Netze (RFC 1918), höchstens 1024 Adressen je Lauf, TCP-Connect auf wenige
Verwaltungsports (kein ICMP/Raw-Socket, keine Exploits, keine Anmeldeversuche), begrenzte Parallelität, ein Lauf
gleichzeitig. Das Ergebnis liefert Typ-Vorschläge für die Geräteliste; übernommen wird nur auf Klick.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PORTS = (22, 23, 80, 161, 443, 445, 514, 3389, 5000, 5985, 8443)
MAX_HOSTS = 1024
CONCURRENCY = 64
TIMEOUT = 0.8
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


class DiscoveryError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_network(cidr: str) -> list[str]:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        raise DiscoveryError("discovery_bad_network") from None
    if net.version != 4 or not any(net.subnet_of(p) for p in PRIVATE):
        raise DiscoveryError("discovery_not_private")
    if net.num_addresses > MAX_HOSTS + 2:
        raise DiscoveryError("discovery_too_large")
    return [str(h) for h in net.hosts()]


def guess_type(ports: list[int]) -> str:
    """Vorschlag für den Gerätetyp (Geräteliste); leer = unbekannt."""
    s = set(ports)
    if 3389 in s or 445 in s and 5985 in s:
        return "windows"
    if 8443 in s and 443 in s:
        return "fortigate" if 514 in s or 22 in s else ""
    if 5000 in s and 445 in s:
        return "synology"
    if 22 in s and not (80 in s or 443 in s):
        return "linux"
    if 161 in s or 23 in s:
        return "arubaos"
    return ""


async def _probe(ip: str, port: int) -> bool:
    try:
        _r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), TIMEOUT)
    except (OSError, TimeoutError):
        return False
    w.close()
    return True


async def _host(ip: str, sem: asyncio.Semaphore) -> dict[str, Any] | None:
    async with sem:
        res = await asyncio.gather(*[_probe(ip, p) for p in PORTS])
    ports = [p for p, ok in zip(PORTS, res, strict=True) if ok]
    if not ports:
        return None
    loop = asyncio.get_running_loop()
    try:
        name = (await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 2))[0]
    except (OSError, TimeoutError):
        name = ""
    return {"ip": ip, "hostname": name, "ports": ports, "suggested_type": guess_type(ports)}


async def scan(ips: list[str]) -> list[dict[str, Any]]:
    sem = asyncio.Semaphore(CONCURRENCY // len(PORTS) + 1)
    found = await asyncio.gather(*[_host(ip, sem) for ip in ips])
    return sorted((f for f in found if f), key=lambda f: ipaddress.ip_address(f["ip"]))


class Scanner:
    """Ein Lauf gleichzeitig; Ergebnis in ``discovery.json``."""

    def __init__(self, path: Path, run=scan) -> None:
        self.path = path
        self._run = run
        self.lock = threading.Lock()

    def state(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            return {"status": "idle", "results": []}

    def _save(self, d: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(d), "utf-8")
        os.replace(tmp, self.path)

    def start(self, cidr: str, actor: str, background: bool = True) -> dict[str, Any]:
        ips = parse_network(cidr)
        with self.lock:
            if self.state().get("status") == "running":
                raise DiscoveryError("discovery_busy")
            self._save({"status": "running", "network": cidr, "hosts": len(ips), "actor": actor, "results": [],
                        "started": datetime.now(UTC).isoformat(timespec="seconds")})
        if background:
            threading.Thread(target=self._work, args=(cidr, ips), daemon=True, name="discovery").start()
        else:
            self._work(cidr, ips)
        return self.state()

    def _work(self, cidr: str, ips: list[str]) -> None:
        base = self.state()
        try:
            results = asyncio.run(self._run(ips))
            self._save({**base, "status": "done", "results": results,
                        "finished": datetime.now(UTC).isoformat(timespec="seconds")})
        except Exception as exc:  # noqa: BLE001 – jeder Fehler beendet den Lauf sauber
            self._save({**base, "status": "failed", "error": str(exc)[:200]})

    def recover(self) -> None:
        """Nach Neustart hängende Läufe beenden."""
        s = self.state()
        if s.get("status") == "running":
            self._save({**s, "status": "failed", "error": "interrupted"})
