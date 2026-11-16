"""Windows-Anbindung (OpenWEC): Eingabeprüfung, Subscriptions, Skript, Keytab, API-Rechte."""

from __future__ import annotations

import base64
import struct
import tomllib

import pytest

from siem_api import wec

SETTINGS = {
    "domain": "firma.local", "fqdn": "siem.firma.local", "service_account": "svc-siem-wec",
    "roles": {"dc": ["OU=Domain Controllers,DC=firma,DC=local"], "member": ["OU=Server,DC=firma,DC=local"],
              "exchange": [], "client": []},
}


def make_keytab(princ: str = "HTTP/siem.firma.local", realm: str = "FIRMA.LOCAL") -> bytes:
    comps = princ.split("/")
    body = struct.pack(">h", len(comps)) + struct.pack(">h", len(realm)) + realm.encode()
    for c in comps:
        body += struct.pack(">h", len(c)) + c.encode()
    body += struct.pack(">iIBhh", 1, 0, 3, 18, 32) + b"k" * 32
    return b"\x05\x02" + struct.pack(">i", len(body)) + body


def test_validate_rejects_injection():
    bad = dict(SETTINGS, roles={"dc": [r"OU=x'; Remove-Item C:\ -Recurse; '"], "member": [], "exchange": [], "client": []})
    with pytest.raises(wec.WecError) as exc:
        wec.validate_settings(bad)
    assert exc.value.code == "wec_invalid_ou"
    for field, code in (("domain", "wec_invalid_domain"), ("fqdn", "wec_invalid_fqdn"), ("service_account", "wec_invalid_account")):
        with pytest.raises(wec.WecError) as exc:
            wec.validate_settings(dict(SETTINGS, **{field: "a b;$(x)"}))
        assert exc.value.code == code


def test_generated_toml_is_valid_for_all_roles():
    conf = tomllib.loads(wec.render_conf(wec.validate_settings(SETTINGS)))
    assert conf["collectors"][0]["authentication"]["service_principal_name"] == "HTTP/siem.firma.local@FIRMA.LOCAL"
    uuids = set()
    for role in wec.ROLES:
        sub = tomllib.loads(wec.render_subscription(role))
        assert sub["name"] == f"siem-{role}" and sub["options"]["uri"] == f"/wec/{role}"
        assert sub["outputs"][0]["config"]["port"] == wec.VECTOR_PORT
        assert "<QueryList>" in sub["query"]
        uuids.add(sub["uuid"])
    assert len(uuids) == 4


def test_queries_respect_xpath_limit():
    import re
    for role in wec.ROLES:
        for sel in wec.role_queries(role):
            assert len(re.findall(r"EventID=\d+", sel)) <= 15


def test_security_events_cover_change_auditing_and_fim():
    q = wec.role_query("dc")
    for eid in (4624, 4625, 4728, 4732, 4768, 4776, 5136, 1102):
        assert f"EventID={eid}" in q
    m = wec.role_query("member")
    for eid in (4688, 4663, 5145, 4698):
        assert f"EventID={eid}" in m


def test_script_contains_settings_and_escapes():
    s = wec.validate_settings(SETTINGS)
    script = wec.render_script(s)
    assert "@@" not in script
    assert "$Fqdn      = 'siem.firma.local'" in script
    assert "dc = @('OU=Domain Controllers,DC=firma,DC=local')" in script
    assert "exchange = @()" in script
    assert "Audit Process Creation" in script and "{0CCE922B-69AE-11D9-BED3-505054503030}" in script
    assert len(wec.script_sha256(script)) == 64


def test_keytab_parser_and_principal_check():
    s = wec.validate_settings(SETTINGS)
    wec.check_keytab(make_keytab(), s)
    with pytest.raises(wec.WecError) as exc:
        wec.check_keytab(make_keytab("HTTP/anders.firma.local"), s)
    assert exc.value.code == "wec_keytab_principal"
    for junk in (b"", b"hallo welt, keine keytab", b"\x05\x02" + b"\xff" * 20):
        with pytest.raises(wec.WecError):
            wec.check_keytab(junk, s)


def test_write_all_removes_unused_roles(tmp_path):
    s = wec.validate_settings(SETTINGS)
    wec.write_all(tmp_path, s)
    assert {p.name for p in (tmp_path / "subscriptions").glob("*.toml")} == {"siem-dc.toml", "siem-member.toml"}
    s["roles"]["member"] = []
    wec.write_all(tmp_path, s)
    assert {p.name for p in (tmp_path / "subscriptions").glob("*.toml")} == {"siem-dc.toml"}
    assert wec.load_settings(tmp_path)["fqdn"] == "siem.firma.local"


# --- API -------------------------------------------------------------------------------------------

def test_api_flow(h, settings):
    h.create_user("adm", ["system-admin"])
    c = h.login("adm")
    assert c.get("/api/wec").json()["configured"] is False
    assert c.get("/api/wec/script").status_code == 409
    assert c.put("/api/wec/settings", json=dict(SETTINGS, fqdn="kein fqdn")).json()["detail"]["error"] == "wec_invalid_fqdn"
    r = c.put("/api/wec/settings", json=SETTINGS)
    assert r.status_code == 200 and r.json()["configured"] and not r.json()["keytab"]
    r = c.get("/api/wec/script")
    assert r.status_code == 200 and r.headers["x-script-sha256"] and "New-GPO" in r.text
    bad = c.put("/api/wec/keytab", json={"keytab_b64": base64.b64encode(make_keytab("HTTP/x.firma.local")).decode()})
    assert bad.json()["detail"]["error"] == "wec_keytab_principal"
    assert c.put("/api/wec/keytab", json={"keytab_b64": "***"}).json()["detail"]["error"] == "wec_keytab_invalid"
    ok = c.put("/api/wec/keytab", json={"keytab_b64": base64.b64encode(make_keytab()).decode()})
    assert ok.status_code == 200 and ok.json()["keytab"] is True
    assert (settings.wec_dir / "krb5.keytab").stat().st_size > 0


def test_api_requires_permissions(h):
    h.create_user("aud", ["auditor"])
    c = h.login("aud")
    assert c.get("/api/wec").status_code == 200
    assert c.put("/api/wec/settings", json=SETTINGS).status_code == 403
    assert c.get("/api/wec/script").status_code == 403
    h.create_user("rep", ["report-recipient"])
    assert h.login("rep").get("/api/wec").status_code == 403


def test_audit_csv_has_header_crlf_and_all_subcategories():
    text = wec.audit_csv()
    lines = text.split("\r\n")
    assert lines[0].startswith("Machine Name,Policy Target,Subcategory,Subcategory GUID")
    assert lines[-1] == "" and len(lines) - 2 == len(wec.recommended_audit_policy())
    row = lines[1].split(",")
    assert row[1] == "System" and row[3].startswith("{") and row[6] in {"1", "2", "3"}


def test_audit_csv_download(h):
    h.create_user("sec", ["security-analyst"])
    r = h.login("sec").get("/api/wec/audit-policy.csv")
    assert r.status_code == 200 and r.content.startswith(b"\xef\xbb\xbfMachine Name")
    assert "audit.csv" in r.headers["content-disposition"]
