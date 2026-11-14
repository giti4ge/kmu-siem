"""SNMP-Poller (v2c/v3): Gerätestatus und Schnittstellen (IF-MIB) alle 60 s → ECS-Ereignisse an Vector.

Je Ziel und Zyklus entsteht ein Status-Ereignis (``snmp.device``) mit allen Schnittstellen; Änderungen des
Betriebszustands (nur bei administrativ aktiven Ports) erzeugen zusätzlich ``port-up``/``port-down``
(``snmp.port``). Fällt ein Gerät dreimal in Folge aus, folgt ``device-unreachable`` (einmalig), danach
``device-recovered``. Die SNMP-Schicht ist austauschbar (``Session``), damit die Auswertung ohne Gerät testbar ist.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any, Protocol

log = logging.getLogger("siem.snmp.poll")

POLL_SECONDS = 60
FAILS_BEFORE_ALARM = 3
MAX_CONCURRENT = 10
MAX_INTERFACES = 512

SYS = {"descr": "1.3.6.1.2.1.1.1.0", "uptime": "1.3.6.1.2.1.1.3.0", "name": "1.3.6.1.2.1.1.5.0"}
IF_COLUMNS = {
    "descr": "1.3.6.1.2.1.2.2.1.2", "admin": "1.3.6.1.2.1.2.2.1.7", "oper": "1.3.6.1.2.1.2.2.1.8",
    "in_errors": "1.3.6.1.2.1.2.2.1.14", "out_errors": "1.3.6.1.2.1.2.2.1.20",
    "name": "1.3.6.1.2.1.31.1.1.1.1", "speed_mbps": "1.3.6.1.2.1.31.1.1.1.15",
}
# FDB: Q-BRIDGE (je VLAN) bevorzugt, BRIDGE-MIB als Rückfall; Bridge-Port → ifIndex über dot1dBasePortIfIndex
QBRIDGE_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
BRIDGE_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
BRIDGE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
FDB_EVERY = 5  # Zyklen (= 5 min bei 60 s)
MAX_FDB = 4096
UPLINK_MACS = 8  # Ports mit mehr gelernten MACs gelten als Uplink/Trunk und liefern keine Asset-Ereignisse
ASSET_REFRESH_SECONDS = 3600
STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}


class Session(Protocol):
    async def get(self, oids: list[str]) -> dict[str, Any]: ...

    async def walk(self, oid: str) -> dict[str, Any]: ...


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


async def collect(session: Session) -> dict[str, Any]:
    """Systemdaten und Schnittstellentabelle lesen (Ausnahmen des Transports gehen an den Aufrufer)."""
    sysvals = await session.get(list(SYS.values()))
    columns = {}
    for key, oid in IF_COLUMNS.items():
        columns[key] = await session.walk(oid)
    ifaces = []
    for suffix in sorted(columns["descr"], key=lambda s: _int(s))[:MAX_INTERFACES]:
        ifaces.append({
            "index": _int(suffix),
            "name": str(columns["name"].get(suffix) or columns["descr"][suffix]),
            "admin": STATUS.get(_int(columns["admin"].get(suffix)), "unknown"),
            "oper": STATUS.get(_int(columns["oper"].get(suffix)), "unknown"),
            "speed_mbps": _int(columns["speed_mbps"].get(suffix)),
            "in_errors": _int(columns["in_errors"].get(suffix)),
            "out_errors": _int(columns["out_errors"].get(suffix)),
        })
    return {"sys_descr": str(sysvals.get(SYS["descr"], "")), "sys_name": str(sysvals.get(SYS["name"], "")),
            "uptime_ticks": _int(sysvals.get(SYS["uptime"])), "interfaces": ifaces}


def _mac(octets: list[str]) -> str | None:
    try:
        vals = [int(o) for o in octets]
    except ValueError:
        return None
    if len(vals) != 6 or any(not 0 <= v <= 255 for v in vals):
        return None
    return ":".join(f"{v:02x}" for v in vals)


async def collect_fdb(session: Session, ifaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """MAC-Adressen je Port/VLAN (nur gelernte Einträge mit gültigem Port)."""
    port_if = await session.walk(BRIDGE_PORT_IFINDEX)
    names = {i["index"]: i["name"] for i in ifaces}
    raw = await session.walk(QBRIDGE_FDB_PORT)
    qbridge = bool(raw)
    if not qbridge:
        raw = await session.walk(BRIDGE_FDB_PORT)
    entries = []
    for suffix, bport in raw.items():
        parts = suffix.split(".")
        vlan = _int(parts[0]) if qbridge else 0
        mac = _mac(parts[1:] if qbridge else parts)
        if_index = _int(port_if.get(str(_int(bport))), _int(bport) if not port_if else 0)
        if mac is None or if_index <= 0:  # Bridge-Port 0 = „selbst“/nicht gelernt
            continue
        entries.append({"mac": mac, "vlan": vlan, "if_index": if_index, "port": names.get(if_index, str(if_index))})
        if len(entries) >= MAX_FDB:
            break
    return sorted(entries, key=lambda e: (e["if_index"], e["vlan"], e["mac"]))


def fdb_event(target: dict[str, Any], entries: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    ev = _base(target, now)
    ev["event"].update({"dataset": "snmp.fdb", "action": "fdb"})
    ev["message"] = f"{target.get('name') or target['ip']}: {len(entries)} MAC-Adressen in der FDB"
    ev["snmp"] = {"fdb": {"count": len(entries), "entries": entries}}
    return ev


def asset_events(target: dict[str, Any], entries: list[dict[str, Any]],
                 known: dict[tuple[str, int], tuple[int, float]], now: datetime) -> list[dict[str, Any]]:
    """Asset-Ereignisse für Endgeräte-Ports (neu, Portwechsel, stündlich); ``known`` wird fortgeschrieben."""
    per_port: dict[int, int] = {}
    for e in entries:
        per_port[e["if_index"]] = per_port.get(e["if_index"], 0) + 1
    out = []
    ts = now.timestamp()
    for e in entries:
        if per_port[e["if_index"]] > UPLINK_MACS:
            continue
        key = (e["mac"], e["vlan"])
        prev = known.get(key)
        if prev and prev[0] == e["if_index"] and ts - prev[1] < ASSET_REFRESH_SECONDS:
            continue
        ev = _base(target, now)
        ev["siem"]["category"] = "asset"
        moved = bool(prev) and prev[0] != e["if_index"]
        ev["event"].update({"dataset": "asset.mac", "action": "asset-moved" if moved else "asset-seen",
                            "category": ["host"]})
        ev["source"] = {"mac": e["mac"]}
        if e["vlan"] > 0:
            ev["network"] = {"vlan": {"id": str(e["vlan"])}}
        ev["observer"]["ingress"] = {"interface": {"name": e["port"]}}
        ev["message"] = f"MAC {e['mac']} an {target.get('name') or target['ip']} Port {e['port']}"
        out.append(ev)
        known[key] = (e["if_index"], ts)
    return out


def _base(target: dict[str, Any], now: datetime) -> dict[str, Any]:
    return {
        "@timestamp": now.isoformat().replace("+00:00", "Z"),
        "siem": {"collector": "snmp", "pipeline": "snmp-poll", "category": target.get("category", "network")},
        "event": {"kind": "event", "module": "snmp", "category": ["network"], "type": ["info"]},
        "observer": {"ip": target["ip"], "name": target.get("name") or target["ip"], "type": "snmp"},
    }


def status_events(target: dict[str, Any], data: dict[str, Any], previous: dict[int, str] | None,
                  now: datetime) -> list[dict[str, Any]]:
    ifaces = data["interfaces"]
    up = sum(1 for i in ifaces if i["oper"] == "up")
    ev = _base(target, now)
    ev["event"].update({"dataset": "snmp.device", "action": "poll"})
    ev["message"] = f"{target.get('name') or target['ip']}: {up}/{len(ifaces)} Schnittstellen aktiv"
    ev["snmp"] = {"sys_descr": data["sys_descr"], "sys_name": data["sys_name"], "uptime_ticks": data["uptime_ticks"],
                  "ports_total": len(ifaces), "ports_up": up, "interfaces": ifaces}
    out = [ev]
    if previous is not None:
        for i in ifaces:
            old = previous.get(i["index"])
            if old is None or old == i["oper"] or i["admin"] != "up":
                continue
            pe = _base(target, now)
            went_up = i["oper"] == "up"
            pe["event"].update({"dataset": "snmp.port", "action": "port-up" if went_up else "port-down",
                                "type": ["change", "start" if went_up else "end"]})
            pe["observer"]["ingress"] = {"interface": {"name": i["name"]}}
            label = target.get("name") or target["ip"]
            pe["message"] = f"{label}: Port {i['name']} {'aktiv' if went_up else 'inaktiv'}"
            pe["snmp"] = {"if_index": i["index"], "oper": i["oper"], "previous": old}
            out.append(pe)
    return out


def failure_event(target: dict[str, Any], action: str, now: datetime, reason: str = "") -> dict[str, Any]:
    ev = _base(target, now)
    ev["event"].update({"dataset": "snmp.device", "action": action,
                        "type": ["error"] if action == "device-unreachable" else ["info"]})
    ev["log"] = {"level": "warning" if action == "device-unreachable" else "info"}
    ev["message"] = f"{target.get('name') or target['ip']}: " + (
        "per SNMP nicht erreichbar" if action == "device-unreachable" else "wieder erreichbar")
    if reason:
        ev["event"]["reason"] = reason
    return ev


class Tracker:
    """Merkt sich Zustand je Ziel (Ports, Ausfallzähler); Zustand geht bei Neustart verloren (nur Folgeänderungen)."""

    def __init__(self) -> None:
        self.ports: dict[str, dict[int, str]] = {}
        self.fails: dict[str, int] = {}
        self.alarmed: set[str] = set()
        self.cycles: dict[str, int] = {}
        self.known: dict[str, dict[tuple[str, int], tuple[int, float]]] = {}

    async def poll_once(self, target: dict[str, Any], session: Session,
                        now: datetime | None = None) -> list[dict[str, Any]]:
        now = now or datetime.now(UTC)
        ip = target["ip"]
        try:
            data = await asyncio.wait_for(collect(session), 45)
        except Exception as exc:  # noqa: BLE001 – jeder Transportfehler zählt als Ausfall
            self.fails[ip] = self.fails.get(ip, 0) + 1
            if self.fails[ip] >= FAILS_BEFORE_ALARM and ip not in self.alarmed:
                self.alarmed.add(ip)
                return [failure_event(target, "device-unreachable", now, type(exc).__name__)]
            return []
        out = status_events(target, data, self.ports.get(ip), now)
        n = self.cycles.get(ip, 0)
        self.cycles[ip] = n + 1
        if n % FDB_EVERY == 0:
            try:
                fdb = await asyncio.wait_for(collect_fdb(session, data["interfaces"]), 45)
                if fdb:  # Geräte ohne (lesbare) BRIDGE-MIB liefern keine FDB-Ereignisse
                    out.append(fdb_event(target, fdb, now))
                    out.extend(asset_events(target, fdb, self.known.setdefault(ip, {}), now))
            except Exception as exc:  # noqa: BLE001 – Gerät ohne BRIDGE-MIB: Status bleibt gültig
                log.info("Ziel %s: keine FDB (%s)", ip, type(exc).__name__)
        self.ports[ip] = {i["index"]: i["oper"] for i in data["interfaces"]}
        self.fails[ip] = 0
        if ip in self.alarmed:
            self.alarmed.discard(ip)
            out.append(failure_event(target, "device-recovered", now))
        return out


class PysnmpSession:
    """Echte SNMP-Abfragen (pysnmp 7, asyncio); ``auth`` ist CommunityData oder UsmUserData."""

    def __init__(self, engine: Any, auth: Any, transport: Any) -> None:
        self.engine, self.auth, self.transport = engine, auth, transport

    async def get(self, oids: list[str]) -> dict[str, Any]:
        from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, get_cmd
        err, status, _idx, vbs = await get_cmd(self.engine, self.auth, self.transport, ContextData(),
                                               *[ObjectType(ObjectIdentity(o)) for o in oids])
        if err or status:
            raise RuntimeError(str(err or status))
        return {str(n.get_oid()): v.prettyPrint() for n, v in vbs}

    async def walk(self, oid: str) -> dict[str, Any]:
        from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, walk_cmd
        out: dict[str, Any] = {}
        prefix = oid + "."
        async for err, status, _idx, vbs in walk_cmd(self.engine, self.auth, self.transport, ContextData(),
                                                     ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
            if err or status:
                raise RuntimeError(str(err or status))
            for n, v in vbs:
                name = str(n.get_oid())
                if name.startswith(prefix):
                    out[name[len(prefix):]] = v.prettyPrint()
            if len(out) >= MAX_INTERFACES:
                break
        return out


async def make_session(target: dict[str, Any], cfg: dict[str, Any], engine: Any) -> PysnmpSession:
    from pysnmp.hlapi.v3arch.asyncio import CommunityData, UdpTransportTarget, UsmUserData

    from . import snmp_config
    transport = await UdpTransportTarget.create((target["ip"], 161), timeout=5, retries=1)
    if target["version"] == "v2c":
        return PysnmpSession(engine, CommunityData(target["community"], mpModel=1), transport)  # noqa: S508 – v2c nur wenn konfiguriert
    user = next((u for u in cfg["v3_users"] if u["user"] == target["user"]), None)
    if user is None:
        raise RuntimeError("v3-Benutzer unbekannt")
    p = snmp_config.protocol_objects()
    if user["priv_proto"] == "none":
        auth = UsmUserData(user["user"], user["auth_key"], authProtocol=p["auth"][user["auth_proto"]])
    else:
        auth = UsmUserData(user["user"], user["auth_key"], user["priv_key"], authProtocol=p["auth"][user["auth_proto"]],
                           privProtocol=p["priv"][user["priv_proto"]])
    return PysnmpSession(engine, auth, transport)


async def run(cfg: dict[str, Any], send, stop: asyncio.Event, interval: float = POLL_SECONDS,
              session_factory=make_session) -> None:
    """Zyklus über alle Ziele (begrenzt parallel) bis ``stop`` gesetzt wird."""
    from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

    targets = cfg.get("targets", [])
    if not targets:
        await stop.wait()
        return
    engine, tracker, sem = SnmpEngine(), Tracker(), asyncio.Semaphore(MAX_CONCURRENT)

    async def one(t: dict[str, Any]) -> None:
        async with sem:
            try:
                session = await session_factory(t, cfg, engine)
            except Exception as exc:  # noqa: BLE001
                log.warning("Ziel %s: %s", t["ip"], exc)
                return
            for ev in await tracker.poll_once(t, session):
                send(ev)

    while not stop.is_set():
        await asyncio.gather(*[one(t) for t in targets])
        try:
            await asyncio.wait_for(stop.wait(), interval)
        except TimeoutError:
            continue
