"""SNMP-Trap-Empfänger (v2c und v3 authPriv/authNoPriv) → ECS-JSON an Vector (127.0.0.1:10602).

Läuft als eigener Container (gleiches Image, ``python -m siem_api.snmp_receiver``, Host-Netz, UDP 10162;
nftables leitet 162 → 10162 um). Zugangsdaten stammen aus ``snmp.json`` im Secrets-Verzeichnis (Schlüssel
AES-256-GCM-verschlüsselt, siehe ``snmp_config``). Änderungen an der Datei beenden den Prozess; Docker startet
ihn mit der neuen Konfiguration neu. Namensauflösung vorerst nur für Standard-Traps; Hersteller-MIBs folgen (4.6b).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import snmp_config, snmp_poller

log = logging.getLogger("siem.snmp")
LISTEN = ("0.0.0.0", 10162)  # noqa: S104 – Trap-Port, Zugriff über nftables begrenzt
VECTOR_ADDR = ("127.0.0.1", 10602)

SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
STANDARD_TRAPS = {
    "1.3.6.1.6.3.1.1.5.1": ("coldStart", "info"),
    "1.3.6.1.6.3.1.1.5.2": ("warmStart", "info"),
    "1.3.6.1.6.3.1.1.5.3": ("linkDown", "warning"),
    "1.3.6.1.6.3.1.1.5.4": ("linkUp", "info"),
    "1.3.6.1.6.3.1.1.5.5": ("authenticationFailure", "warning"),
    "1.3.6.1.6.3.1.1.5.6": ("egpNeighborLoss", "warning"),
}
IF_INDEX_PREFIX = "1.3.6.1.2.1.2.2.1.1."
IF_OPER_PREFIX = "1.3.6.1.2.1.2.2.1.8."
IF_ADMIN_PREFIX = "1.3.6.1.2.1.2.2.1.7."


def trap_event(source_ip: str, varbinds: list[tuple[str, str]], now: datetime | None = None,
               version: str = "v2c", user: str | None = None) -> dict[str, Any]:
    """Trap nach ECS abbilden (reine Funktion, testbar)."""
    vb = dict(varbinds)
    oid = vb.get(SNMP_TRAP_OID, "")
    name, severity = STANDARD_TRAPS.get(oid, (oid or "unknown", "info"))
    ts = (now or datetime.now(UTC)).isoformat().replace("+00:00", "Z")
    raw = {k: v for k, v in varbinds}
    ev: dict[str, Any] = {
        "@timestamp": ts,
        "siem": {"collector": "snmp", "pipeline": "snmp-trap", "category": "network"},
        "event": {"kind": "event", "module": "snmp", "dataset": "snmp.trap", "action": name, "code": oid or None,
                  "category": ["network"], "type": ["info"],
                  "severity": {"info": 6, "warning": 4}.get(severity, 6),
                  "original": json.dumps(raw, sort_keys=True)[:8000]},
        "observer": {"ip": source_ip, "type": "snmp"},
        "log": {"level": severity},
        "message": f"SNMP-Trap {name} von {source_ip}",
        "snmp": {"version": version, "trap_oid": oid, "uptime": vb.get(SYS_UPTIME),
                 "varbinds": [{"oid": k, "value": v} for k, v in varbinds if k not in (SNMP_TRAP_OID, SYS_UPTIME)]},
    }
    if user:
        ev["snmp"]["user"] = user
    if name in ("linkDown", "linkUp"):
        idx = next((v for k, v in varbinds if k.startswith(IF_INDEX_PREFIX)), None)
        if idx is not None:
            ev["observer"]["ingress"] = {"interface": {"name": f"ifIndex {idx}"}}
        ev["event"]["type"] = ["change", "end" if name == "linkDown" else "start"]
        ev["event"]["action"] = "port-down" if name == "linkDown" else "port-up"
    if name == "authenticationFailure":
        ev["event"]["category"] = ["authentication"]
        ev["event"]["outcome"] = "failure"
    return ev


def send_to_vector(event: dict[str, Any], addr: tuple[str, int] = VECTOR_ADDR) -> None:
    try:
        with socket.create_connection(addr, timeout=5) as s:
            s.sendall((json.dumps(event) + "\n").encode())
    except OSError:
        log.warning("Vector nicht erreichbar, Trap verworfen")


async def run(secrets_dir: Path, master_key: bytes, listen: tuple[str, int] = LISTEN, send=send_to_vector,
              watch_seconds: float = 10.0, stop: asyncio.Event | None = None,
              poll_interval: float = snmp_poller.POLL_SECONDS) -> None:
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config, engine
    from pysnmp.entity.rfc3413 import ntfrcv

    cfg = snmp_config.load_runtime(secrets_dir, master_key)
    eng = engine.SnmpEngine()
    config.add_transport(eng, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(listen))
    for i, community in enumerate(cfg["communities"]):
        config.add_v1_system(eng, f"c{i}", community)
    protos = snmp_config.protocol_objects()
    from pysnmp.proto.rfc1902 import OctetString

    for u in cfg["v3_users"]:
        auth = protos["auth"][u["auth_proto"]]
        keys = (auth, u["auth_key"]) if u["priv_proto"] == "none" else (
            auth, u["auth_key"], protos["priv"][u["priv_proto"]], u["priv_key"])
        config.add_v3_user(eng, u["user"], *keys)  # Informs: Empfänger ist autoritativ
        if u["engine_id"]:  # v3-Traps: Engine-ID des Senders ist vorab nötig
            config.add_v3_user(eng, u["user"], *keys, securityEngineId=OctetString(hexValue=u["engine_id"]))

    # Sicherheitsmodell/-name je Absenderadresse merken (v2c = Modell 2, v3 = Modell 3); Observer und Callback
    # laufen direkt nacheinander im selben Event-Loop-Durchlauf
    sec_info: dict[Any, tuple[int, str]] = {}

    def on_receive(_eng, _exec_point, variables, _ctx):
        key = tuple(variables["transportAddress"])
        sec_info[key] = (int(variables["securityModel"]), str(variables["securityName"]))

    eng.observer.register_observer(on_receive, "rfc3412.receiveMessage:request")

    def on_trap(snmp_engine, state_ref, ctx_engine_id, ctx_name, var_binds, _ctx):
        _, addr = snmp_engine.message_dispatcher.get_transport_info(state_ref)
        model, name = sec_info.pop(tuple(addr), (2, ""))
        vbs = [(str(n.prettyPrint()), str(v.prettyPrint())) for n, v in var_binds]
        send(trap_event(str(addr[0]), vbs, version="v3" if model == 3 else "v2c", user=name if model == 3 else None))

    ntfrcv.NotificationReceiver(eng, on_trap)
    path = snmp_config.config_path(secrets_dir)
    start_mtime = path.stat().st_mtime if path.exists() else 0
    stop = stop or asyncio.Event()
    log.info("SNMP-Trap-Empfänger auf %s:%s (%d Communities, %d v3-Benutzer)", listen[0], listen[1],
             len(cfg["communities"]), len(cfg["v3_users"]))
    poll_task = asyncio.create_task(snmp_poller.run(cfg, send, stop, interval=poll_interval))
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), watch_seconds)
        except TimeoutError:
            if (path.stat().st_mtime if path.exists() else 0) != start_mtime:
                log.info("Konfiguration geändert – Neustart")
                break
    stop.set()
    await poll_task
    eng.close_dispatcher() if hasattr(eng, "close_dispatcher") else eng.closeDispatcher()


def main() -> None:
    from .config import get_settings
    from .security.keys import KeyRing

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = get_settings()
    keys = KeyRing(settings.secrets_dir)
    asyncio.run(run(settings.secrets_dir, keys.master_key))
    sys.exit(0 if os.environ.get("SIEM_SNMP_ONESHOT") else 3)  # Exit ≠ 0 → Docker startet neu (restart: always)


if __name__ == "__main__":
    main()
