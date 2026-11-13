"""Geräteliste: Validierung, devices.csv für Vector, API-Rechte."""

from __future__ import annotations

import pytest

from siem_api import devices as dev


def test_validate_and_csv():
    assert dev.validate(" 10.0.0.1 ", "Core Switch", "arubaos") == ("10.0.0.1", "Core Switch", "arubaos")
    assert dev.validate("2001:DB8::1", "fw-1", "fortigate")[0] == "2001:db8::1"
    for args, code in ((("10.0.0", "x", "linux"), "device_invalid_ip"),
                       (("10.0.0.1", "a,b", "linux"), "device_invalid_name"),
                       (("10.0.0.1", "x\nhack", "linux"), "device_invalid_name"),
                       (("10.0.0.1", "x", "bogus"), "device_invalid_type")):
        with pytest.raises(dev.DeviceError) as exc:
            dev.validate(*args)
        assert exc.value.code == code
    assert dev.render_csv([("10.0.0.2", "linux"), ("10.0.0.1", "arubaos")]) == "ip,type\n10.0.0.1,arubaos\n10.0.0.2,linux\n"


def test_api_crud_writes_csv(h, settings):
    h.create_user("adm", ["system-admin"])
    c = h.login("adm")
    body = {"ip": "10.0.0.7", "name": "SW-Keller", "type": "arubaos", "note": "Serverraum"}
    r = c.post("/api/devices", json=body)
    assert r.status_code == 201 and r.json()["applied"] is False  # hostd im Test nicht vorhanden
    assert (settings.vector_dir / "devices.csv").read_text() == "ip,type\n10.0.0.7,arubaos\n"
    assert c.post("/api/devices", json=body).json()["detail"]["error"] == "device_exists"
    assert c.post("/api/devices", json=dict(body, ip="x")).json()["detail"]["error"] == "device_invalid_ip"
    did = r.json()["id"]
    r = c.put(f"/api/devices/{did}", json=dict(body, type="fs_s3900"))
    assert r.status_code == 200
    assert "10.0.0.7,fs_s3900" in (settings.vector_dir / "devices.csv").read_text()
    assert [d["name"] for d in c.get("/api/devices").json()["devices"]] == ["SW-Keller"]
    assert c.delete(f"/api/devices/{did}").status_code == 204
    assert (settings.vector_dir / "devices.csv").read_text() == "ip,type\n"
    assert c.delete(f"/api/devices/{did}").json()["detail"]["error"] == "device_not_found"


def test_api_permissions(h):
    h.create_user("aud", ["auditor"])
    c = h.login("aud")
    assert c.get("/api/devices").status_code == 200
    assert c.post("/api/devices", json={"ip": "10.0.0.1", "name": "x", "type": "linux"}).status_code == 403
