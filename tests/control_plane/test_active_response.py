"""Active Response: Schutzliste, Sperren/Entsperren/Ablauf, Obergrenzen, automatische Sperre mit Rate-Limit."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from siem_api import active_response as ar
from siem_api import fortigate

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


class Fake:
    def __init__(self, status: int = 200) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []
        self.status = status

    def __call__(self, method, path, fcfg, token, body=None, timeout=20.0):
        self.calls.append((method, path, body))
        return self.status, {}


def stores(tmp_path: Path, **over):
    fs = fortigate.Store(tmp_path, b"k" * 32)
    fs.save(enabled=True, host="fw.example.org", port=443, vdom="root", tls_pin="", token="t")
    s = ar.Store(tmp_path, b"k" * 32)
    s.save({"enabled": True, "auto": False, "group": "SIEM_BLOCK", "hours": 24, "protected": [], **over}, "schreib-token")
    return s, fs


@pytest.mark.parametrize("ip,ok", [("203.0.113.9", True), ("10.1.2.3", False), ("192.168.1.1", False), ("127.0.0.1", False),
                                   ("169.254.1.1", False), ("8.8.8.8", True), ("nonsense", False), ("2001:db8::1", False)])
def test_protected_ips(ip, ok):
    if ok:
        assert ar.check_ip(ip, []) == ip
    else:
        with pytest.raises(ar.ARError):
            ar.check_ip(ip, [])


def test_custom_protection_list(tmp_path):
    with pytest.raises(ar.ARError) as e:
        ar.check_ip("8.8.8.8", ["8.8.8.0/24"])
    assert e.value.code == "ar_protected_ip"


def test_token_encrypted(tmp_path):
    s, _ = stores(tmp_path)
    assert "schreib-token" not in (tmp_path / "active-response.json").read_text("utf-8")
    assert s.token() == "schreib-token" and s.config()["has_token"]


def test_disabled_by_default(tmp_path):
    s, fs = stores(tmp_path, enabled=False)
    with pytest.raises(ar.ARError) as e:
        ar.block(s, fs, "203.0.113.9", None, "x", "u", Fake())
    assert e.value.code == "ar_disabled"


def test_block_unblock_and_calls(tmp_path):
    s, fs = stores(tmp_path)
    f = Fake()
    e = ar.block(s, fs, "203.0.113.9", 2, "Test", "admin", f, NOW)
    assert e["until"] == (NOW + timedelta(hours=2)).isoformat(timespec="seconds")
    assert f.calls[0][1] == "/api/v2/cmdb/firewall/address" and f.calls[0][2]["subnet"] == "203.0.113.9 255.255.255.255"
    assert f.calls[1][1] == "/api/v2/cmdb/firewall/addrgrp/SIEM_BLOCK/member"
    assert [b["ip"] for b in s.blocks()] == ["203.0.113.9"]
    assert ar.unblock(s, fs, "203.0.113.9", f) is True and s.blocks() == []
    assert any(c[0] == "DELETE" and c[1].endswith("/member/siem-block-203_0_113_9") for c in f.calls)
    assert ar.unblock(s, fs, "203.0.113.9", f) is False


def test_expiry(tmp_path):
    s, fs = stores(tmp_path)
    f = Fake()
    ar.block(s, fs, "203.0.113.9", 1, "a", "u", f, NOW)
    ar.block(s, fs, "203.0.113.10", 10, "b", "u", f, NOW)
    assert ar.expire(s, fs, NOW + timedelta(hours=2), f) == ["203.0.113.9"]
    assert [b["ip"] for b in s.blocks()] == ["203.0.113.10"]


def test_group_missing_and_forti_error(tmp_path):
    s, fs = stores(tmp_path)

    class G(Fake):
        def __call__(self, method, path, *a, **k):
            super().__call__(method, path, *a, **k)
            return (404, {}) if "addrgrp" in path else (200, {})

    with pytest.raises(ar.ARError) as e:
        ar.block(s, fs, "203.0.113.9", None, "x", "u", G(), NOW)
    assert e.value.code == "ar_group_missing" and s.blocks() == []
    with pytest.raises(ar.ARError):
        ar.block(s, fs, "203.0.113.9", None, "x", "u", Fake(403), NOW)


def test_limit_and_auto_rate(tmp_path, monkeypatch):
    s, fs = stores(tmp_path)
    f = Fake()
    monkeypatch.setattr(ar, "AUTO_PER_HOUR", 2)
    ar.block(s, fs, "203.0.113.1", None, "x", "auto", f, NOW, auto=True)
    ar.block(s, fs, "203.0.113.2", None, "x", "auto", f, NOW, auto=True)
    with pytest.raises(ar.ARError) as e:
        ar.block(s, fs, "203.0.113.3", None, "x", "auto", f, NOW, auto=True)
    assert e.value.code == "ar_auto_rate_limit"
    ar.block(s, fs, "203.0.113.3", None, "x", "admin", f, NOW)  # manuell nicht begrenzt
    monkeypatch.setattr(ar, "MAX_ACTIVE", 3)
    with pytest.raises(ar.ARError) as e2:
        ar.block(s, fs, "203.0.113.4", None, "x", "admin", f, NOW)
    assert e2.value.code == "ar_limit_reached"


def test_auto_candidate():
    a = {"rule": {"id": "win-bruteforce-ip", "group_by": "source.ip"}, "severity": "high", "group": "203.0.113.9"}
    assert ar.auto_candidate(a) == "203.0.113.9"
    assert ar.auto_candidate({**a, "severity": "medium"}) is None
    assert ar.auto_candidate({**a, "rule": {"id": "win-log-cleared", "group_by": "host.name"}}) is None


def test_api_requires_login(app):
    from fastapi.testclient import TestClient
    c = TestClient(app)
    assert c.get("/api/ar").status_code in (401, 403)
    assert c.post("/api/ar/block", json={"ip": "8.8.8.8"}).status_code in (401, 403)
