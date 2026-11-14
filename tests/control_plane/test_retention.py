"""Retention je Kategorie: Richtlinien-Umbau, Plausibilisierung, API-Rechte."""

from __future__ import annotations

from siem_api.routers import retention as rt


def policy(days: int, seq: int = 1) -> dict:
    return {"_seq_no": seq, "_primary_term": 1, "policy": {
        "policy_id": "x", "description": "d", "default_state": "hot", "last_updated_time": 1,
        "states": [
            {"name": "hot", "actions": [], "transitions": [{"state_name": "warm", "conditions": {"min_index_age": "7d"}}]},
            {"name": "warm", "actions": [{"read_only": {}}], "transitions": [{"state_name": "delete", "conditions": {"min_index_age": f"{days}d"}}]},
            {"name": "delete", "actions": [{"delete": {}}], "transitions": []}],
        "ism_template": [{"index_patterns": ["siem-x-*"], "priority": 100}]}}


class Stub:
    def __init__(self, total=10_000_000_000, size=1_000_000):
        self.calls, self.total, self.size = [], total, size

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path.startswith("/_plugins/_ism/policies/") and method == "GET":
            return policy(180)
        if path.startswith("/_cat/indices"):
            return [{"index": "siem-windows-2026.11.01", "store.size": str(self.size)},
                    {"index": "siem-windows-2026.11.02", "store.size": str(self.size)}]
        if path.startswith("/_nodes/stats/fs"):
            return {"nodes": {"n1": {"fs": {"total": {"total_in_bytes": self.total}}}}}
        return {}


def test_delete_days_and_with_days():
    assert rt.delete_days(policy(90)) == 90
    new = rt.with_days(policy(90), "windows", 3 + 4)
    assert rt.delete_days(new) == 7 and "last_updated_time" not in new["policy"] and "policy_id" not in new["policy"]
    short = rt.with_days(policy(90), "windows", 7)
    assert short["policy"]["states"][0]["transitions"][0]["conditions"]["min_index_age"] == "6d"


def test_daily_bytes_and_storage_check():
    per = rt.daily_bytes([{"index": "siem-windows-1", "store.size": "100"}, {"index": "siem-windows-2", "store.size": "300"},
                          {"index": "andere-x-1", "store.size": "5"}])
    assert per == {"windows": 200.0}
    assert rt.storage_check({"windows": 10}, per, 10_000)["ok"] is True
    assert rt.storage_check({"windows": 100}, per, 10_000)["ok"] is False


def test_api_get_put_and_limits(h, monkeypatch):
    h.create_user("adm", ["system-admin"])
    h.create_user("ana", ["security-analyst"])
    stub = Stub()
    monkeypatch.setattr(rt, "client_for", lambda request: stub)
    c = h.login("adm")
    r = c.get("/api/retention")
    assert r.status_code == 200
    win = next(x for x in r.json()["categories"] if x["category"] == "windows")
    assert win["days"] == 180 and win["daily_bytes"] == 1_000_000
    r = c.put("/api/retention", json={"days": {"windows": 90}})
    assert r.status_code == 200
    puts = [x for x in stub.calls if x[0] == "PUT"]
    assert len(puts) == 1 and "siem-windows" in puts[0][1] and "if_seq_no=1" in puts[0][1]
    assert any(x[0] == "POST" and "change_policy" in x[1] for x in stub.calls)
    assert c.put("/api/retention", json={"days": {"windows": 3}}).json()["detail"]["error"] == "retention_out_of_range"
    assert c.put("/api/retention", json={"days": {"bogus": 30}}).json()["detail"]["error"] == "retention_unknown_category"
    stub.total = 1_000_000_000  # 12 Kategorien à 180 d bei 1 MB/d wären ok, 730 d für windows nicht
    stub.size = 100_000_000
    assert c.put("/api/retention", json={"days": {"windows": 730}}).json()["detail"]["error"] == "retention_exceeds_storage"
    assert h.login("ana").get("/api/retention").status_code == 403
