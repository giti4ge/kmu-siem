"""SNMP-Poller gegen einen echten pysnmp-Agenten über Loopback (IF-MIB-Tabelle, GET/WALK, v2c)."""

from __future__ import annotations

import asyncio
import socket

import pytest

pytest.importorskip("pysnmp")

from pysnmp.carrier.asyncio.dgram import udp  # noqa: E402
from pysnmp.entity import config, engine  # noqa: E402
from pysnmp.entity.rfc3413 import cmdrsp, context  # noqa: E402
from pysnmp.hlapi.v3arch.asyncio import CommunityData, SnmpEngine, UdpTransportTarget  # noqa: E402
from pysnmp.proto import rfc1902  # noqa: E402

from siem_api import snmp_poller as sp  # noqa: E402

PORTS = [("Gi1", 1, 1, 0), ("Gi2", 1, 2, 5), ("Gi3", 2, 2, 0)]  # Name, admin, oper, out_errors


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_agent(port: int):
    eng = engine.SnmpEngine()
    config.add_transport(eng, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", port)))
    config.add_v1_system(eng, "area", "public-comm1")
    config.add_vacm_user(eng, 2, "area", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))
    ctx = context.SnmpContext(eng)
    mb = ctx.get_mib_instrum().get_mib_builder()
    scalar, instance = mb.import_symbols("SNMPv2-SMI", "MibScalar", "MibScalarInstance")
    syms: dict = {}

    def add(oid: str, inst: tuple, val) -> None:
        t = tuple(int(x) for x in oid.split("."))
        syms[f"s{len(syms)}"] = scalar(t, type(val)()).setMaxAccess("read-only")
        syms[f"i{len(syms)}"] = instance(t, inst, val)

    c = sp.IF_COLUMNS
    for idx, (name, admin, oper, out_err) in enumerate(PORTS, start=1):
        add(c["descr"], (idx,), rfc1902.OctetString(name))
        add(c["name"], (idx,), rfc1902.OctetString(name))
        add(c["admin"], (idx,), rfc1902.Integer(admin))
        add(c["oper"], (idx,), rfc1902.Integer(oper))
        add(c["in_errors"], (idx,), rfc1902.Counter32(0))
        add(c["out_errors"], (idx,), rfc1902.Counter32(out_err))
        add(c["speed_mbps"], (idx,), rfc1902.Gauge32(1000))
    mb.export_symbols("__TEST-MIB", **syms)
    cmdrsp.GetCommandResponder(eng, ctx)
    cmdrsp.NextCommandResponder(eng, ctx)
    cmdrsp.BulkCommandResponder(eng, ctx)
    return eng


def test_collect_and_poll_against_real_agent():
    port = free_port()

    async def scenario():
        agent = build_agent(port)
        transport = await UdpTransportTarget.create(("127.0.0.1", port), timeout=2, retries=0)
        session = sp.PysnmpSession(SnmpEngine(), CommunityData("public-comm1", mpModel=1), transport)  # noqa: S508
        events = await sp.Tracker().poll_once({"ip": "127.0.0.1", "name": "agent", "version": "v2c"}, session)
        agent.close_dispatcher()
        return events

    events = asyncio.run(asyncio.wait_for(scenario(), 30))
    dev = events[0]
    assert dev["event"]["dataset"] == "snmp.device" and dev["snmp"]["ports_total"] == 3 and dev["snmp"]["ports_up"] == 1
    names = [i["name"] for i in dev["snmp"]["interfaces"]]
    assert names == ["Gi1", "Gi2", "Gi3"]
    assert dev["snmp"]["interfaces"][1]["out_errors"] == 5 and dev["snmp"]["interfaces"][1]["speed_mbps"] == 1000
    assert dev["snmp"]["interfaces"][2]["admin"] == "down"
