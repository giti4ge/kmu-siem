"""Phase 4 Rest: LLDP, Geräteprofile (Hardwarezustand), MIB-Import, Discovery-Scanner."""

from __future__ import annotations

import asyncio
import base64
import io
import zipfile
from datetime import UTC, datetime

import pytest
from test_snmp_poller import FakeSession

from siem_api import discovery as dc
from siem_api import mibs
from siem_api import snmp_poller as sp
from siem_api import snmp_profiles as pr

NOW = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
LLDP_NAME = pr.LLDP_REM["sys_name"]


class ProfSession(FakeSession):
    def __init__(self, values=None, lldp=True):
        super().__init__()
        self.values = values or {}
        self.lldp = lldp

    async def get(self, oids):
        if oids[0] in self.values:
            return {oids[0]: self.values[oids[0]]}
        if oids[0] in (sp.SYS["descr"], *sp.SYS.values()):
            return await super().get(oids)
        return {oids[0]: "No Such Object available"}

    async def walk(self, oid):
        if oid == LLDP_NAME:
            return {"0.3.1": "core-sw"} if self.lldp else {}
        if oid == pr.LLDP_REM["port_id"]:
            return {"0.3.1": "Gi1/0/48"} if self.lldp else {}
        if oid.startswith("1.0.8802"):
            return {}
        return await super().walk(oid)


def poll(tracker, target, session):
    return asyncio.run(tracker.poll_once(target, session, NOW))


def test_judge() -> None:
    spec = {"ok": {"3"}, "warn": {"4"}, "crit": {"5", "6"}}
    assert [pr.judge(spec, v) for v in ("3", "4", "5", "9")] == ["ok", "warn", "critical", "warn"]
    assert pr.judge({"max": 70}, "75") == "warn" and pr.judge({"max": 70}, "40") == "ok"
    assert pr.judge({}, "x") == "info"


def test_hardware_event_on_change_only() -> None:
    t = sp.Tracker()
    target = {"ip": "10.0.0.9", "name": "nas", "profile": "synology", "category": "infra"}
    oid_status = pr.PROFILES["synology"]["scalars"]["system_status"]["oid"]
    ok = ProfSession({oid_status: "1"})
    ev = [e for e in poll(t, target, ok) if e["event"]["dataset"] == "snmp.hardware"]
    assert ev and ev[0]["event"]["action"] == "hardware-ok" and ev[0]["siem"]["category"] == "infra"
    assert not [e for e in poll(t, target, ok) if e["event"]["dataset"] == "snmp.hardware"]  # unverändert
    bad = ProfSession({oid_status: "2"})
    ev = [e for e in poll(t, target, bad) if e["event"]["dataset"] == "snmp.hardware"]
    assert ev[0]["event"]["action"] == "hardware-critical" and "system_status=2" in ev[0]["message"]
    assert ev[0]["log"]["level"] == "error"


def test_lldp_event() -> None:
    t = sp.Tracker()
    target = {"ip": "10.0.0.5", "name": "sw", "profile": "generic"}
    evs = [e for e in poll(t, target, ProfSession()) if e["event"]["dataset"] == "snmp.lldp"]
    assert evs and evs[0]["snmp"]["lldp"]["neighbors"][0] == {
        "local_port": "3", "remote_name": "core-sw", "remote_port": "Gi1/0/48", "remote_chassis": ""}
    assert not [e for e in poll(t, target, ProfSession()) if e["event"]["dataset"] == "snmp.lldp"]  # keine Änderung


def test_custom_oid_profile() -> None:
    sc = pr.scalars_for("custom", [{"name": "temp", "oid": "1.3.6.1.4.1.9.9.13.1.3.1.3.1"}])
    assert sc["custom_temp"]["oid"] == "1.3.6.1.4.1.9.9.13.1.3.1.3.1"


MIB = """
EXAMPLE-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM SNMPv2-SMI;
-- Kommentar { fake 99 }
example OBJECT IDENTIFIER ::= { enterprises 99999 }
exTemp OBJECT-TYPE
    SYNTAX Integer32
    ACCESS read-only
    ::= { exMon 1 }
exMon OBJECT IDENTIFIER ::= { example 2 }
END
"""


def test_mib_import_resolves_and_searches(tmp_path) -> None:
    s = mibs.Store(tmp_path / "mibs")
    r = s.add("example.mib", MIB.encode())
    assert r == {"module": "EXAMPLE-MIB", "objects": 3, "unresolved": 0}
    assert s.resolve("exTemp") == "1.3.6.1.4.1.99999.2.1"
    assert s.search("temp") == [{"module": "EXAMPLE-MIB", "name": "exTemp", "oid": "1.3.6.1.4.1.99999.2.1"}]
    assert s.remove("EXAMPLE-MIB") and s.modules() == []


def test_mib_rejects_binary_and_garbage(tmp_path) -> None:
    s = mibs.Store(tmp_path / "m")
    with pytest.raises(mibs.MibError):
        s.add("x.mib", b"\x00\x01binary")
    with pytest.raises(mibs.MibError):
        s.add("x.mib", b"kein mib")
    with pytest.raises(mibs.MibError):
        s.add("../x.mib", MIB.encode())
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a/EXAMPLE.mib", MIB)
        z.writestr("evil.exe", b"MZ")
    assert s.add_zip(buf.getvalue())[0]["module"] == "EXAMPLE-MIB"


def test_discovery_network_rules() -> None:
    assert len(dc.parse_network("192.168.1.0/30")) == 2
    for bad in ("8.8.8.0/24", "10.0.0.0/8", "x", "192.168.0.0/16", "::1/128"):
        with pytest.raises(dc.DiscoveryError):
            dc.parse_network(bad)
    assert dc.guess_type([3389, 445]) == "windows" and dc.guess_type([22]) == "linux" and dc.guess_type([]) == ""


def test_discovery_scanner_flow(tmp_path) -> None:
    async def fake(ips):
        return [{"ip": ips[0], "hostname": "h", "ports": [22], "suggested_type": "linux"}]

    sc = dc.Scanner(tmp_path / "d.json", run=fake)
    res = sc.start("192.168.5.0/29", "adm", background=False)
    assert res["status"] == "done" and res["results"][0]["ip"] == "192.168.5.1"
    sc._save({"status": "running"})
    with pytest.raises(dc.DiscoveryError):
        sc.start("192.168.5.0/29", "adm", background=False)
    sc.recover()
    assert sc.state()["status"] == "failed"


def test_discovery_real_probe_localhost() -> None:
    import socket
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert asyncio.run(dc._probe("127.0.0.1", port)) is True
    finally:
        srv.close()
    assert asyncio.run(dc._probe("127.0.0.1", port)) is False


def test_api_mib_and_discovery(app, h):
    h.create_user("adm", ["system-admin"])
    h.create_user("aud", ["auditor"])
    adm, aud = h.login("adm"), h.login("aud")
    r = adm.post("/api/snmp/mibs", json={"filename": "example.mib", "content": MIB})
    assert r.status_code == 200 and r.json()["result"]["objects"] == 3
    assert adm.get("/api/snmp/mibs", params={"q": "temp"}).json()["matches"][0]["name"] == "exTemp"
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("e.mib", MIB)
    assert adm.post("/api/snmp/mibs", json={"filename": "p.zip", "content_b64": base64.b64encode(z.getvalue()).decode()}).status_code == 200
    assert adm.post("/api/snmp/mibs", json={"filename": "x.mib", "content": "müll"}).status_code == 422
    assert aud.post("/api/snmp/mibs", json={"filename": "x.mib", "content": MIB}).status_code == 403
    assert adm.delete("/api/snmp/mibs/EXAMPLE-MIB").status_code == 200
    assert adm.post("/api/discovery", json={"network": "8.8.8.0/24"}).status_code == 422
    assert aud.get("/api/discovery").json()["status"] == "idle"
    assert adm.get("/api/snmp/profiles").json()[0]["id"] == "generic"
    t = {"ip": "10.0.0.7", "name": "nas", "version": "v2c", "community": "geheim-community", "profile": "synology",
         "category": "infra", "custom_oids": [{"name": "temp", "oid": "1.3.6.1.4.1.99999.2.1.0"}]}
    assert adm.put("/api/snmp", json={"targets": [t], "v3_users": []}).json()["targets"][0]["profile"] == "synology"
    assert adm.put("/api/snmp", json={"targets": [{**t, "profile": "bogus"}], "v3_users": []}).status_code == 400


# ---- Rückwirkende Verarbeitung ----
class ReplayOS:
    def __init__(self):
        self.calls = []

    def search(self, index, body):
        doc = {"_index": "siem-unparsed-2026.11.13", "_id": "i1", "_source": {
            "@timestamp": "2026-11-13T09:00:00Z", "observer": {"ip": "10.0.20.5"}, "host": {"hostname": "srv"},
            "process": {"name": "sshd", "pid": 7}, "event": {"original": "Failed password for x"},
            "log": {"syslog": {"severity": {"name": "info"}}}}}
        return {"hits": {"total": {"value": 1}, "hits": [doc, {"_index": "x", "_id": "i2", "_source": {}}]}}

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        return {}


def test_replay_builds_lines_and_deletes_originals():
    from siem_api import replay
    sent = []
    res = replay.replay_source(ReplayOS(), "10.0.20.5", sender=sent.append)
    assert res == {"replayed": 1, "remaining": 0}
    assert sent[0][0] == {"source_ip": "10.0.20.5", "message": "Failed password for x",
                          "@timestamp": "2026-11-13T09:00:00Z", "hostname": "srv", "appname": "sshd", "procid": 7,
                          "severity": "info"}


def test_api_replay_requires_device(app, h, monkeypatch):
    h.create_user("adm", ["system-admin"])
    adm = h.login("adm")
    assert adm.post("/api/logs/unparsed/replay", json={"ip": "10.0.20.5"}).status_code == 409
    adm.post("/api/devices", json={"ip": "10.0.20.5", "name": "srv", "type": "linux"})
    from siem_api.routers import logs
    fake = ReplayOS()
    monkeypatch.setattr(logs, "client_for", lambda _r: fake)
    app.state.replay_sender = lambda lines: None
    r = adm.post("/api/logs/unparsed/replay", json={"ip": "10.0.20.5"})
    assert r.status_code == 200 and r.json()["replayed"] == 1
    assert any("_delete_by_query" in c[1] for c in fake.calls)


# ---- Parser-Editor ----
RULE = {"id": "mailgw", "name": "Mail-Gateway", "program": "mgw", "category": "network",
        "regex": r"reject (?P<ip>\S+) user=(?P<user>\S+) code=(?P<code>\d+)",
        "fields": {"ip": "source.ip", "user": "user.name", "code": "destination.port"}, "action": "mail-reject"}


def test_parser_rule_validation_and_render():
    from siem_api import custom_parsers as cp
    ok = cp.validate_rule(RULE)
    vrl = cp.render_vrl([ok])
    assert 'parse_regex(string(.event.original) ?? ""' in vrl and '.siem.category = "network"' in vrl
    assert "ip_pton" in vrl and "to_int(m.code)" in vrl and '.process.name == "mgw"' in vrl
    assert cp.render_vrl([]).strip().endswith(". = .")
    for bad in (
        {**RULE, "regex": r"(?=x)(?P<ip>.)"}, {**RULE, "regex": "it's (?P<ip>.)(?P<user>.)(?P<code>.)"},
        {**RULE, "category": "audit"}, {**RULE, "fields": {"nope": "user.name"}},
        {**RULE, "fields": {"ip": "event.kind"}}, {**RULE, "id": "Bad Id"}, {**RULE, "regex": "(unclosed"},
        {**RULE, "fields": {"ip": "user.name", "user": "user.name"}},
    ):
        with pytest.raises(cp.ParserError):
            cp.validate_rule(bad)


def test_parser_rule_test_and_store(tmp_path):
    from siem_api import custom_parsers as cp
    res = cp.test_rule(RULE, ["reject 1.2.3.4 user=max code=550", "nichts"], program="mgw")
    assert res[0]["match"] and res[0]["fields"] == {"source.ip": "1.2.3.4", "user.name": "max",
                                                    "destination.port": "550"}
    assert not res[1]["match"]
    assert not cp.test_rule(RULE, ["reject 1.2.3.4 user=max code=550"], program="andere")[0]["match"]
    st = cp.Store(tmp_path)
    st.ensure_default()
    assert (tmp_path / "custom.vrl").read_text().endswith(". = .\n")
    st.save([RULE])
    assert st.rules()[0]["id"] == "mailgw" and "mailgw" in (tmp_path / "custom.vrl").read_text()


def test_api_parsers(app, h, monkeypatch):
    from siem_api import hostd
    calls = []
    monkeypatch.setattr(hostd, "call", lambda sock, action, params, actor="": calls.append(action) or {})
    h.create_user("adm", ["system-admin"])
    h.create_user("aud", ["auditor"])
    adm, aud = h.login("adm"), h.login("aud")
    assert aud.put("/api/parsers", json={"rules": [RULE]}).status_code == 403
    sample = {"rule": RULE, "samples": ["reject 1.1.1.1 user=a code=1"]}
    assert adm.post("/api/parsers/test", json=sample).json()[0]["match"]
    r = adm.put("/api/parsers", json={"rules": [RULE]})
    assert r.status_code == 200 and r.json()["applied"] and calls == ["vector.restart"]
    assert adm.put("/api/parsers", json={"rules": [{**RULE, "regex": "(?=a)(?P<ip>.)"}]}).status_code == 422
    assert aud.get("/api/parsers").json()["rules"][0]["id"] == "mailgw"
