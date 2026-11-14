"""Asset-Center: Aufbereitung der Aggregation, Abfrage, Rechte."""

from __future__ import annotations

from siem_api.routers import assets

RESP = {"aggregations": {"mac": {"buckets": [
    {"key": "aa:bb:cc:00:00:01", "doc_count": 3, "first": {"value_as_string": "2026-11-01T10:00:00Z"},
     "last": {"value_as_string": "2026-11-14T09:00:00Z"},
     "latest": {"hits": {"hits": [{"_source": {"observer": {"name": "SW1", "ip": "10.0.0.2",
                                                          "ingress": {"interface": {"name": "Gi1/0/5"}}},
                                               "network": {"vlan": {"id": "10"}}}}]}}},
    {"key": "aa:bb:cc:00:00:02", "doc_count": 1, "first": {"value_as_string": "2026-11-14T10:00:00Z"},
     "last": {"value_as_string": "2026-11-14T10:00:00Z"}, "latest": {"hits": {"hits": []}}},
]}}}


def test_parse_orders_by_last_seen_and_tolerates_missing_fields():
    rows = assets.parse(RESP)
    assert [r["mac"] for r in rows] == ["aa:bb:cc:00:00:02", "aa:bb:cc:00:00:01"]
    full = rows[1]
    assert (full["switch"], full["port"], full["vlan"], full["first_seen"]) == ("SW1", "Gi1/0/5", "10", "2026-11-01T10:00:00Z")
    assert rows[0]["switch"] is None and rows[0]["port"] is None
    assert assets.parse({}) == []


def test_query_and_api(h, monkeypatch):
    q = assets.build_query(7)
    assert "now-7d" in str(q) and "asset.mac" in str(q) and q["aggs"]["mac"]["terms"]["field"] == "source.mac"

    class Stub:
        def search(self, index, body):
            self.index = index
            return RESP

    stub = Stub()
    monkeypatch.setattr(assets, "client_for", lambda request: stub)
    h.create_user("ana", ["security-analyst"])
    h.create_user("rep", ["report-recipient"])
    r = h.login("ana").get("/api/assets?days=14")
    assert r.status_code == 200 and len(r.json()["assets"]) == 2 and stub.index == "siem-asset-*"
    assert h.login("ana").get("/api/assets?days=0").status_code == 422
    assert h.login("rep").get("/api/assets").status_code == 403
