"""Alert-Engine: Abfrageaufbau, Auswertung, Alarm-Upsert ohne Wiederöffnen, Regelverwaltung, Rechte."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from siem_api import alerts as al

NOW = datetime(2026, 11, 14, 10, 0).astimezone()


def rule(rid: str) -> al.Rule:
    return next(r for r in al.BUILTIN_RULES if r.id == rid)


def test_builtin_rules_are_consistent():
    ids = [r.id for r in al.BUILTIN_RULES]
    assert len(ids) == len(set(ids)) >= 15
    for r in al.BUILTIN_RULES:
        assert r.severity in al.SEVERITIES and r.filters and r.threshold >= 1 and r.mitre


def test_query_group_threshold_and_distinct():
    q = al.build_query(rule("win-bruteforce-ip"))
    assert {"terms": {"winlog.event_id": ["4625"]}} in q["query"]["bool"]["filter"]
    g = q["aggs"]["g"]
    assert g["terms"]["field"] == "source.ip" and g["terms"]["min_doc_count"] == 10 and q["size"] == 0
    d = al.build_query(rule("fw-portscan"))["aggs"]["g"]["aggs"]
    assert d["distinct"] == {"cardinality": {"field": "destination.port"}}
    m = al.build_query(rule("win-log-cleared"))  # ohne Schwelle >1 weiterhin gruppiert (host.name)
    assert m["aggs"]["g"]["terms"]["min_doc_count"] == 1


def _bucket(key: str, n: int, distinct: int | None = None) -> dict:
    b = {"key": key, "doc_count": n, "last": {"value_as_string": "2026-11-14T09:59:00Z"},
         "sample": {"hits": {"hits": [{"_source": {"message": "beispiel"}}]}}}
    if distinct is not None:
        b["distinct"] = {"value": distinct}
    return b


def test_evaluate_distinct_filters_small_cardinality():
    resp = {"aggregations": {"g": {"buckets": [_bucket("10.0.0.5", 120, 45), _bucket("10.0.0.6", 120, 3)]}}}
    out = al.evaluate(rule("fw-portscan"), resp)
    assert [c["group"] for c in out] == ["10.0.0.5"] and out[0]["distinct"] == 45


def test_evaluate_ungrouped_uses_total():
    r = al.Rule("x", "X", "low", "d", {"a": ["b"]}, threshold=2)
    assert al.evaluate(r, {"hits": {"total": {"value": 1}, "hits": []}}) == []
    out = al.evaluate(r, {"hits": {"total": {"value": 3}, "hits": [{"_source": {"@timestamp": "t", "message": "m"}}]}})
    assert out[0]["count"] == 3


class FakeOS:
    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}
        self.matches: dict[str, dict] = {}

    def search(self, index: str, body: dict) -> dict:
        for rid, resp in self.matches.items():
            if al.build_query(rule(rid)) == body:
                return resp
        return {}

    def request(self, method: str, path: str, body: Any = None) -> Any:
        assert method == "POST" and "/_update/" in path
        aid = path.split("/_update/")[1].split("?")[0]
        if aid in self.docs:
            self.docs[aid]["alert"].update(body["doc"]["alert"])
            return {"result": "updated"}
        self.docs[aid] = body["upsert"]
        return {"result": "created"}


def test_cycle_creates_once_and_notifies_once(tmp_path: Path):
    fos = FakeOS()
    fos.matches["win-bruteforce-ip"] = {"aggregations": {"g": {"buckets": [_bucket("10.0.0.5", 25)]}}}
    store = al.RuleStore(tmp_path / "rules.json")
    sent: list = []
    s1 = al.run_cycle(fos, store, NOW, sent.append)  # type: ignore[arg-type]
    s2 = al.run_cycle(fos, store, NOW, sent.append)  # type: ignore[arg-type]
    assert s1["created"] == 1 and s2["created"] == 0 and len(sent) == 1
    doc = next(iter(fos.docs.values()))
    assert doc["alert"]["status"] == "open" and doc["alert"]["severity"] == "high" and doc["rule"]["id"] == "win-bruteforce-ip"
    assert sent[0]["group"] == "10.0.0.5" and sent[0]["severity"] == "high"
    # Bestätigter Alarm bleibt bestätigt, Zähler wird aktualisiert
    doc["alert"]["status"] = "acknowledged"
    fos.matches["win-bruteforce-ip"] = {"aggregations": {"g": {"buckets": [_bucket("10.0.0.5", 40)]}}}
    al.run_cycle(fos, store, NOW, sent.append)  # type: ignore[arg-type]
    assert doc["alert"]["status"] == "acknowledged" and doc["alert"]["count"] == 40 and len(sent) == 1


def test_rule_overrides(tmp_path: Path):
    store = al.RuleStore(tmp_path / "rules.json")
    store.update("win-bruteforce-ip", {"enabled": False, "severity": "critical", "threshold": 3})
    store.update("fw-portscan", {"severity": "bogus", "threshold": 0})  # ungültig → ignoriert
    rules = {r.id: r for r in store.rules()}
    assert rules["win-bruteforce-ip"].enabled is False and rules["win-bruteforce-ip"].severity == "critical"
    assert rules["win-bruteforce-ip"].threshold == 3 and rules["fw-portscan"].severity == "medium"
    fos = FakeOS()
    fos.matches["win-bruteforce-ip"] = {"aggregations": {"g": {"buckets": [_bucket("1.1.1.1", 99)]}}}
    assert al.run_cycle(fos, store, NOW)["created"] == 0  # deaktiviert  # type: ignore[arg-type]


def test_api_requires_login(app):
    from fastapi.testclient import TestClient
    c = TestClient(app)
    for method, path in (("get", "/api/alerts"), ("get", "/api/alerts/rules"), ("put", "/api/alerts/rules/win-log-cleared")):
        assert getattr(c, method)(path).status_code in (401, 403)
