"""Port-Matrix: Aufbereitung des jüngsten Status je Gerät, Veraltet-Erkennung, Rechte."""

from __future__ import annotations

from datetime import UTC, datetime

from siem_api.routers import switches

NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC)


def bucket(ip, ts, name="SW1"):
    return {"key": ip, "last": {"hits": {"hits": [{"_source": {
        "@timestamp": ts, "observer": {"name": name},
        "snmp": {"sys_descr": "ArubaOS", "uptime_ticks": 5, "ports_total": 2, "ports_up": 1,
                 "interfaces": [{"index": 1, "name": "1", "admin": "up", "oper": "up"},
                                {"index": 2, "name": "2", "admin": "up", "oper": "down"}]}}}]}}}


def test_parse_sorts_and_marks_stale():
    resp = {"aggregations": {"dev": {"buckets": [bucket("10.0.0.3", "2026-11-14T11:59:30Z", "zz-switch"),
                                                 bucket("10.0.0.2", "2026-11-14T11:30:00Z", "AA-switch")]}}}
    devs = switches.parse(resp, NOW)
    assert [d["name"] for d in devs] == ["AA-switch", "zz-switch"]
    assert devs[0]["stale"] is True and devs[1]["stale"] is False and devs[1]["ports_up"] == 1
    assert switches.parse({}, NOW) == []


def test_fdb_counts_per_port_and_uplink_hint():
    devs = switches.parse({"aggregations": {"dev": {"buckets": [bucket("10.0.0.2", "2026-11-14T11:59:30Z")]}}}, NOW)
    entries = [{"mac": "aa:bb:cc:00:00:01", "vlan": 10, "if_index": 2, "port": "2"},
               {"mac": "aa:bb:cc:00:00:02", "vlan": 10, "if_index": 2, "port": "2"}]
    fdb_resp = {"aggregations": {"dev": {"buckets": [
        {"key": "10.0.0.2", "last": {"hits": {"hits": [{"_source": {"snmp": {"fdb": {"entries": entries}}}}]}}}]}}}
    switches.attach_fdb(devs, switches.parse_fdb(fdb_resp))
    assert [i["macs"] for i in devs[0]["interfaces"]] == [0, 2] and len(devs[0]["fdb"]) == 2


def test_query_filters_poll_events():
    q = switches.build_query(6)
    assert "now-6h" in str(q) and "snmp.device" in str(q) and q["aggs"]["dev"]["terms"]["field"] == "observer.ip"


def test_api(h, monkeypatch):
    class Stub:
        def search(self, index, body):
            self.index = index
            if "snmp.fdb" in str(body):
                return {}
            return {"aggregations": {"dev": {"buckets": [bucket("10.0.0.2", "2026-11-14T11:59:30Z")]}}}

    stub = Stub()
    monkeypatch.setattr(switches, "client_for", lambda request: stub)
    h.create_user("ana", ["security-analyst"])
    h.create_user("rep", ["report-recipient"])
    r = h.login("ana").get("/api/switches")
    assert r.status_code == 200 and r.json()["devices"][0]["ports_total"] == 2 and "siem-network-*" in stub.index
    assert h.login("rep").get("/api/switches").status_code == 403
