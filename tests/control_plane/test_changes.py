"""Change-Timeline: Paarung alt → neu, Abfrage, Rechte."""

from __future__ import annotations

from siem_api.routers import changes


def hit(ts, op, attr="description", val="x", actor="hadmin", obj="CN=Max,DC=f,DC=local", **extra):
    ch = {"operation": op, "actor": actor, "object": obj, "attribute": attr, "new_value": val, **extra}
    return {"_source": {"@timestamp": ts, "host": {"name": "dc1"}, "event": {"action": "ad-object-modified"}, "siem": {"change": ch}}}


def test_pairs_delete_and_add_into_old_new():
    rows = changes.pair_changes([
        hit("2026-11-14T10:00:02Z", "value-added", val="neu"),
        hit("2026-11-14T10:00:01Z", "value-deleted", val="alt"),
        hit("2026-11-14T09:00:00Z", "value-added", attr="mail", val="a@b"),
    ])
    assert len(rows) == 2
    assert (rows[0]["old_value"], rows[0]["new_value"]) == ("alt", "neu")
    assert rows[1]["old_value"] is None and rows[1]["attribute"] == "mail"


def test_no_pairing_across_actor_or_time_and_lone_delete_kept():
    rows = changes.pair_changes([
        hit("2026-11-14T10:00:00Z", "value-deleted", val="alt"),
        hit("2026-11-14T10:01:00Z", "value-added", val="neu"),
        hit("2026-11-14T10:00:01Z", "value-added", val="andere", actor="anderer"),
    ])
    assert len(rows) == 3
    lone = next(r for r in rows if r["operation"] == "value-deleted")
    assert lone["old_value"] == "alt" and lone["new_value"] is None
    assert all(r["old_value"] is None for r in rows if r["operation"] == "value-added")


def test_query_and_api(h, monkeypatch):
    q = changes.build_query(6, "Domain Admins", True, 50)
    assert "now-6h" in str(q) and "siem.change.privileged" in str(q) and q["size"] == 50

    class Stub:
        def search(self, index, body):
            self.index, self.body = index, body
            return {"hits": {"hits": [hit("2026-11-14T10:00:00Z", "member-added", attr=None, privileged=True)]}}

    stub = Stub()
    monkeypatch.setattr(changes, "client_for", lambda request: stub)
    h.create_user("ana", ["security-analyst"])
    h.create_user("rep", ["report-recipient"])
    r = h.login("ana").get("/api/changes?hours=12&privileged=true")
    assert r.status_code == 200 and r.json()["changes"][0]["privileged"] is True and stub.index == "siem-windows-*"
    assert h.login("rep").get("/api/changes").status_code == 403
