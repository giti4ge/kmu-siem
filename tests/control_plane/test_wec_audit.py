"""Audit-Policy-Check: Upload-Prüfung, Soll-Ist-Vergleich, API."""

from __future__ import annotations

import json

import pytest

from siem_api import wec, wec_audit


def full_report(computer="srv1", drop=None, value=None):
    rec = wec.recommended_audit_policy()
    settings = []
    for r in rec:
        v = int(r["success"]) | (int(r["failure"]) << 1)
        if r["subcategory"] == drop:
            v = value if value is not None else 0
        settings.append({"guid": r["guid"], "value": v})
    return {"computer": computer, "collected": "2026-11-14T10:00:00Z", "settings": settings}


def test_validate_rejects_garbage():
    for bad in ([], {"computer": "a b", "settings": []}, {"computer": "x", "settings": [{"guid": "nope", "value": 1}]},
                {"computer": "x", "settings": [{"guid": "{0CCE923F-69AE-11D9-BED3-505054503030}", "value": 9}]},
                {"computer": "x; rm", "settings": [{"guid": "{0CCE923F-69AE-11D9-BED3-505054503030}", "value": 1}]}):
        with pytest.raises(wec.WecError):
            wec_audit.validate_upload(bad)


def test_compliant_server_and_deviation():
    ok = wec_audit.validate_upload(full_report())[0]
    assert wec_audit.evaluate(ok["settings"]) == []
    bad = wec_audit.validate_upload(full_report("srv2", drop="Process Creation", value=0))[0]
    dev = wec_audit.evaluate(bad["settings"])
    assert [d["subcategory"] for d in dev] == ["Process Creation"] and dev[0]["missing_success"] is True
    # Nur Failure fehlt (Success vorhanden)
    part = wec_audit.validate_upload(full_report("srv3", drop="Logon", value=1))[0]
    d = wec_audit.evaluate(part["settings"])[0]
    assert d["missing_failure"] is True and d["missing_success"] is False
    # Mehr als empfohlen ist keine Abweichung
    more = wec_audit.validate_upload(full_report("srv4", drop="Logoff", value=3))[0]
    assert wec_audit.evaluate(more["settings"]) == []


def test_save_keeps_latest_per_server(tmp_path):
    wec_audit.save(tmp_path, wec_audit.validate_upload([full_report("A"), full_report("B", drop="Logon", value=0)]))
    wec_audit.save(tmp_path, wec_audit.validate_upload(full_report("b")))  # Name wird kleingeschrieben
    rows = wec_audit.view(wec_audit.load(tmp_path))
    assert [r["computer"] for r in rows] == ["a", "b"]


def test_api_upload_and_permissions(h):
    h.create_user("adm", ["system-admin"])
    h.create_user("aud", ["auditor"])
    c = h.login("adm")
    body = json.dumps([full_report("dc1"), full_report("srv2", drop="File System", value=0)])
    r = c.post("/api/wec/audit-check", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    rows = {x["computer"]: x for x in r.json()["servers"]}
    assert rows["dc1"]["ok"] is True and rows["srv2"]["ok"] is False
    assert c.post("/api/wec/audit-check", content="{kaputt", headers={"Content-Type": "application/json"}).status_code == 400
    assert "auditpol" in c.get("/api/wec/audit-check/script").text
    a = h.login("aud")
    assert a.get("/api/wec/audit-check").status_code == 200
    assert a.post("/api/wec/audit-check", content=body, headers={"Content-Type": "application/json"}).status_code == 403
