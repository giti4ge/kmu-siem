"""Ereignis-Übersichten (Unparsed, Volumen) mit gestubtem OpenSearch."""

from __future__ import annotations

from siem_api.opensearch import OpenSearchUnavailable
from siem_api.routers import logs

UNPARSED = {"aggregations": {"sources": {"buckets": [
    {"key": ["10.0.0.9", "foo"], "doc_count": 5, "last": {"value_as_string": "2026-11-13T10:00:00Z"},
     "samples": {"hits": {"hits": [{"_source": {"event": {"original": "rätselhaft"}, "host": {"hostname": "box"}}}]}}},
    {"key": ["10.0.0.8", ""], "doc_count": 50, "last": {"value_as_string": None},
     "samples": {"hits": {"hits": []}}},
]}}}


class Stub:
    def __init__(self, resp=None, fail=False):
        self.resp, self.fail, self.calls = resp, fail, []

    def search(self, index, body):
        self.calls.append((index, body))
        if self.fail:
            raise OpenSearchUnavailable("x")
        return self.resp


def test_parse_unparsed_sorted_by_count():
    rows = logs.parse_unparsed(UNPARSED)
    assert [r["ip"] for r in rows] == ["10.0.0.8", "10.0.0.9"]
    assert rows[1]["samples"] == ["rätselhaft"] and rows[1]["hostname"] == "box"
    assert logs.parse_unparsed({}) == []


def test_api_unparsed_and_volume(h, monkeypatch):
    h.create_user("ana", ["security-analyst"])
    c = h.login("ana")
    stub = Stub(UNPARSED)
    monkeypatch.setattr(logs, "client_for", lambda request: stub)
    r = c.get("/api/logs/unparsed?hours=6")
    assert r.status_code == 200 and r.json()["sources"][0]["count"] == 50
    assert stub.calls[0][0] == "siem-unparsed-*" and "now-6h" in str(stub.calls[0][1])
    stub.resp = {"aggregations": {"cat": {"buckets": [{"key": "windows", "doc_count": 7}]}}}
    r = c.get("/api/logs/volume")
    assert r.json()["categories"]["windows"] == 7 and r.json()["categories"]["infra"] == 0
    assert c.get("/api/logs/unparsed?hours=0").status_code == 422


def test_opensearch_down_and_permissions(h, monkeypatch):
    h.create_user("ana", ["security-analyst"])
    monkeypatch.setattr(logs, "client_for", lambda request: Stub(fail=True))
    assert h.login("ana").get("/api/logs/unparsed").json()["detail"]["error"] == "opensearch_unavailable"
    h.create_user("rep", ["report-recipient"])
    assert h.login("rep").get("/api/logs/unparsed").status_code == 403
