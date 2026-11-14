"""FortiGate-API: Normalisierung (ARP/DHCP), Änderungs-/Spoofing-Erkennung, Zyklus, Einstellungen, Rechte."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from siem_api import fortigate as fg
from siem_api import sophos

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
ARP = [{"ip": "10.0.10.21", "mac": "AA:BB:CC:00:00:01", "interface": "vlan10"},
       {"ip": "10.0.10.22", "mac": "aa:bb:cc:00:00:02", "interface": "vlan10"},
       {"ip": "10.0.10.99", "mac": "00:00:00:00:00:00", "interface": "vlan10"}]
DHCP = [{"ip": "10.0.10.21", "mac": "aa:bb:cc:00:00:01", "hostname": "pc-mueller", "interface": "vlan10"}]


def test_events_merge_arp_and_dhcp_and_skip_invalid():
    mem: dict = {}
    ev = fg.build_events(ARP, DHCP, mem, NOW, "fw1")
    by_mac = {e["source"]["mac"]: e for e in ev}
    assert set(by_mac) == {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}  # Null-MAC verworfen
    a = by_mac["aa:bb:cc:00:00:01"]
    assert a["host"]["hostname"] == "pc-mueller" and a["source"]["ip"] == "10.0.10.21" and a["siem"]["category"] == "asset"
    assert a["event"]["dataset"] == "fortigate.dhcp" and by_mac["aa:bb:cc:00:00:02"]["event"]["dataset"] == "fortigate.arp"
    assert a["observer"]["ingress"]["interface"]["name"] == "vlan10"
    assert fg.build_events(ARP, DHCP, mem, NOW, "fw1") == []  # unverändert und frisch


def test_ip_mac_change_detected_and_refresh():
    mem: dict = {}
    fg.build_events(ARP, DHCP, mem, NOW, "fw1")
    spoof = [{"ip": "10.0.10.21", "mac": "de:ad:be:ef:00:01", "interface": "vlan10"}]
    ev = fg.build_events(spoof, [], mem, NOW, "fw1")
    assert len(ev) == 1 and ev[0]["event"]["action"] == "ip-mac-changed" and "aa:bb:cc:00:00:01" in ev[0]["event"]["reason"]
    later = datetime.fromtimestamp(NOW.timestamp() + fg.REFRESH_SECONDS + 1, UTC)
    assert len(fg.build_events(ARP[1:2], [], mem, later, "fw1")) == 1  # stündliche Auffrischung


@pytest.fixture
def store(tmp_path):
    s = fg.Store(tmp_path, b"k" * 32)
    s.save(enabled=True, host="fw.firma.local", port=443, vdom="root", tls_pin="AA:" * 31 + "AA", token="geheimes-token")
    return s


def test_settings_validation_and_secret_at_rest(store):
    assert "geheimes-token" not in store.cfg_path.read_text() and store.token() == "geheimes-token"
    assert store.config()["tls_pin"] == "aa" * 32 and store.config()["has_token"] is True
    store.save(enabled=False, host="fw.firma.local", port=443, vdom="root", tls_pin="", token=None)
    assert store.token() == "geheimes-token"
    for kw in (dict(host="a b;c"), dict(port=0), dict(vdom="x y"), dict(tls_pin="zz")):
        args = dict(enabled=True, host="fw", port=443, vdom="root", tls_pin="", token=None) | kw
        with pytest.raises(fg.FortiError):
            store.save(**args)


def test_cycle_sends_and_records_errors(store):
    sent = []

    def get(host, port, path, token, pin):
        assert (host, token) == ("fw.firma.local", "geheimes-token") and "vdom=root" in path
        return {"results": ARP if "arp" in path else DHCP}

    r = fg.run_cycle(store, send=sent.extend, get=get, now=NOW)
    assert r["error"] is None and r["sent"] == 2 and r["arp"] == 3 and r["dhcp"] == 1 and len(sent) == 2
    assert fg.run_cycle(store, send=sent.extend, get=get, now=NOW)["sent"] == 0

    def deny(*_args):
        raise fg.FortiError("fortigate_auth_failed")

    assert fg.run_cycle(store, send=sent.extend, get=deny, now=NOW)["error"] == "fortigate_auth_failed"


def test_failed_delivery_does_not_mark_events_as_seen(store):
    def get(host, port, path, token, pin):
        return {"results": ARP if "arp" in path else DHCP}

    def broken(_events):
        raise sophos.SophosError("sophos_vector_unavailable")

    assert fg.run_cycle(store, send=broken, get=get, now=NOW)["error"] == "fortigate_vector_unavailable"
    sent = []
    assert fg.run_cycle(store, send=sent.extend, get=get, now=NOW)["sent"] == 2  # beim nächsten Mal nachgeliefert


def test_api_never_returns_token_and_permissions(h):
    h.create_user("adm", ["system-admin"])
    h.create_user("ana", ["security-analyst"])
    c = h.login("adm")
    r = c.put("/api/fortigate/settings", json={"enabled": False, "host": "fw.firma.local", "token": "geheimes-token"})
    assert r.status_code == 200 and "geheimes-token" not in r.text and r.json()["config"]["has_token"] is True
    bad = c.put("/api/fortigate/settings", json={"enabled": False, "host": "a b"})
    assert bad.json()["detail"]["error"] == "fortigate_invalid_host"
    assert h.login("ana").get("/api/fortigate").status_code == 200
    assert h.login("ana").put("/api/fortigate/settings", json={"enabled": False, "host": "x"}).status_code == 403
