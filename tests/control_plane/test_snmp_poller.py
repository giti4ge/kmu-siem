"""SNMP-Poller: Auswertung (Status, Port-Wechsel, Ausfall/Erholung) mit simulierter SNMP-Schicht, Ziel-Konfiguration."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from siem_api import snmp_config
from siem_api import snmp_poller as sp

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
TARGET = {"ip": "10.0.0.2", "name": "SW-Keller", "version": "v2c", "community": "public-comm1"}
KEY = b"k" * 32


class FakeSession:
    def __init__(self, oper=None, fail=False, fdb=None):
        self.oper, self.fail, self.fdb = oper or {"1": 1, "2": 2}, fail, fdb or {}

    async def get(self, oids):
        if self.fail:
            raise TimeoutError("keine Antwort")
        return {sp.SYS["descr"]: "ArubaOS", sp.SYS["name"]: "sw1", sp.SYS["uptime"]: "12345"}

    async def walk(self, oid):
        if self.fail:
            raise TimeoutError("keine Antwort")
        c = sp.IF_COLUMNS
        if oid == c["descr"]:
            return {"1": "1", "2": "2"}
        if oid == c["name"]:
            return {"1": "Gi1/0/1", "2": "Gi1/0/2"}
        if oid == c["admin"]:
            return {"1": "1", "2": "1"}
        if oid == c["oper"]:
            return {k: str(v) for k, v in self.oper.items()}
        if oid == c["speed_mbps"]:
            return {"1": "1000", "2": "0"}
        if oid.startswith("1.3.6.1.2.1.17"):
            return self.fdb.get(oid, {})
        return {"1": "0", "2": "3"}


def run(coro):
    return asyncio.run(coro)


def test_fdb_qbridge_and_fallback_and_schedule():
    q = {sp.BRIDGE_PORT_IFINDEX: {"1": "1", "2": "2"},
         sp.QBRIDGE_FDB_PORT: {"10.0.17.34.1.2.3": "2", "20.0.17.34.1.2.4": "1",
                               "10.1.2.3": "1", "10.0.0.0.0.0.1": "0"}}  # letzte zwei: ungültige MAC, Port 0
    entries = run(sp.collect_fdb(FakeSession(fdb=q), [{"index": 1, "name": "Gi1"}, {"index": 2, "name": "Gi2"}]))
    assert [(e["port"], e["vlan"], e["mac"]) for e in entries] == [
        ("Gi1", 20, "00:11:22:01:02:04"), ("Gi2", 10, "00:11:22:01:02:03")]
    # BRIDGE-MIB-Rückfall (kein VLAN) und Zeitplan: FDB im 1. Zyklus, dann erst nach FDB_EVERY Zyklen
    fb = {sp.BRIDGE_PORT_IFINDEX: {"1": "1"}, sp.BRIDGE_FDB_PORT: {"0.17.34.1.2.3": "1"}}
    tr = sp.Tracker()
    first = run(tr.poll_once(TARGET, FakeSession(fdb=fb), NOW))
    assert [e["event"]["dataset"] for e in first] == ["snmp.device", "snmp.fdb"]
    assert first[1]["snmp"]["fdb"]["entries"] == [{"mac": "00:11:22:01:02:03", "vlan": 0, "if_index": 1, "port": "Gi1/0/1"}]
    for _ in range(sp.FDB_EVERY - 1):
        assert [e["event"]["dataset"] for e in run(tr.poll_once(TARGET, FakeSession(fdb=fb), NOW))] == ["snmp.device"]
    assert "snmp.fdb" in [e["event"]["dataset"] for e in run(tr.poll_once(TARGET, FakeSession(fdb=fb), NOW))]


def test_status_event_and_port_change():
    tr = sp.Tracker()
    first = run(tr.poll_once(TARGET, FakeSession(), NOW))
    assert len(first) == 1 and first[0]["event"]["dataset"] == "snmp.device"
    assert first[0]["snmp"]["ports_total"] == 2 and first[0]["snmp"]["ports_up"] == 1
    assert first[0]["snmp"]["interfaces"][0]["name"] == "Gi1/0/1" and first[0]["snmp"]["interfaces"][1]["out_errors"] == 3
    again = run(tr.poll_once(TARGET, FakeSession({"1": 2, "2": 1}), NOW))
    actions = sorted(e["event"]["action"] for e in again)
    assert actions == ["poll", "port-down", "port-up"]
    down = next(e for e in again if e["event"]["action"] == "port-down")
    assert down["observer"]["ingress"]["interface"]["name"] == "Gi1/0/1" and down["snmp"]["previous"] == "up"
    assert [e["event"]["action"] for e in run(tr.poll_once(TARGET, FakeSession({"1": 2, "2": 1}), NOW))] == ["poll"]


def test_unreachable_once_then_recovered():
    tr = sp.Tracker()
    evs = []
    for _ in range(5):
        evs += run(tr.poll_once(TARGET, FakeSession(fail=True), NOW))
    assert [e["event"]["action"] for e in evs] == ["device-unreachable"]  # genau einmal nach 3 Fehlschlägen
    back = run(tr.poll_once(TARGET, FakeSession(), NOW))
    assert [e["event"]["action"] for e in back] == ["poll", "device-recovered"]


def test_admin_down_port_changes_are_ignored():
    class AdminDown(FakeSession):
        async def walk(self, oid):
            if oid == sp.IF_COLUMNS["admin"]:
                return {"1": "2", "2": "1"}
            return await super().walk(oid)

    tr = sp.Tracker()
    run(tr.poll_once(TARGET, AdminDown(), NOW))
    evs = run(tr.poll_once(TARGET, AdminDown({"1": 2, "2": 2}), NOW))
    assert [e["event"]["action"] for e in evs] == ["poll"]  # Port 1 administrativ aus → keine Meldung


def test_targets_config(tmp_path):
    users = [{"user": "siem", "auth_proto": "sha", "auth_key": "authpass123", "priv_proto": "aes128", "priv_key": "privpass123"}]
    targets = [{"ip": "10.0.0.2", "name": "SW1", "version": "v2c", "community": "public-comm1"},
               {"ip": "10.0.0.3", "name": "SW2", "version": "v3", "user": "siem", "category": "infra"}]
    snmp_config.save(tmp_path, KEY, [], users, targets)
    assert "public-comm1" not in snmp_config.config_path(tmp_path).read_text()
    v = snmp_config.view(tmp_path)["targets"]
    assert v[0]["has_community"] is True and "community" not in v[0] and v[1]["category"] == "infra"
    # Community bleibt bei Neuspeichern ohne Eingabe erhalten
    snmp_config.save(tmp_path, KEY, None, users, [dict(targets[0], community=None), targets[1]])
    rt = snmp_config.load_runtime(tmp_path, KEY)
    assert rt["targets"][0]["community"] == "public-comm1" and rt["targets"][1]["user"] == "siem"
    for bad in ([{"ip": "x", "version": "v2c", "community": "public-comm1"}],
                [{"ip": "10.0.0.9", "version": "v3", "user": "unbekannt"}],
                [targets[0], targets[0]],
                [{"ip": "10.0.0.9", "name": "a;b", "version": "v2c", "community": "public-comm1"}]):
        with pytest.raises(snmp_config.SnmpConfigError):
            snmp_config.save(tmp_path, KEY, None, users, bad)


def test_api_targets_roundtrip_and_permissions(h):
    h.create_user("adm", ["system-admin"])
    h.create_user("aud", ["auditor"])
    c = h.login("adm")
    users = [{"user": "siem", "auth_proto": "sha256", "auth_key": "authpass123", "priv_proto": "aes256", "priv_key": "privpass123"}]
    body = {"v3_users": users, "targets": [{"ip": "10.0.0.3", "name": "SW2", "version": "v3", "user": "siem"},
                                           {"ip": "10.0.0.2", "version": "v2c", "community": "public-comm1"}]}
    r = c.put("/api/snmp", json=body)
    assert r.status_code == 200 and [t["ip"] for t in r.json()["targets"]] == ["10.0.0.3", "10.0.0.2"]
    assert "public-comm1" not in r.text and r.json()["targets"][1]["has_community"] is True
    bad = c.put("/api/snmp", json=dict(body, targets=[{"ip": "kein-ip", "version": "v2c", "community": "public-comm1"}]))
    assert bad.json()["detail"]["error"] == "snmp_invalid_target"
    assert h.login("aud").put("/api/snmp", json=body).status_code == 403
