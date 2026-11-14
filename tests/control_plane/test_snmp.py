"""SNMP: Konfiguration (verschlüsselt), Trap → ECS, Ende-zu-Ende-Empfang v2c und v3 über Loopback."""

from __future__ import annotations

import asyncio
import socket

import pytest

from siem_api import snmp_config, snmp_receiver

KEY = b"k" * 32
USERS = [{"user": "siem", "auth_proto": "sha", "auth_key": "authpass123", "priv_proto": "aes128", "priv_key": "privpass123"}]


def test_config_encrypted_and_secret_kept(tmp_path):
    snmp_config.save(tmp_path, KEY, ["public-comm1"], USERS)
    raw = snmp_config.config_path(tmp_path).read_text()
    assert "authpass123" not in raw and "public-comm1" not in raw
    assert snmp_config.view(tmp_path) == {"communities": 1, "v3_users": [{"user": "siem", "auth_proto": "sha", "priv_proto": "aes128"}]}
    snmp_config.save(tmp_path, KEY, None, [dict(USERS[0], auth_key=None, priv_key=None)])  # Schlüssel bleiben
    rt = snmp_config.load_runtime(tmp_path, KEY)
    assert rt["communities"] == ["public-comm1"] and rt["v3_users"][0]["auth_key"] == "authpass123"


@pytest.mark.parametrize("users,comm,code", [
    ([dict(USERS[0], user="a b")], [], "snmp_invalid_user"),
    ([dict(USERS[0], auth_key="kurz")], [], "snmp_invalid_key"),
    ([dict(USERS[0], auth_proto="md5")], [], "snmp_invalid_user"),
    ([], ["x y"], "snmp_invalid_community"),
    ([dict(USERS[0], auth_key=None)], [], "snmp_invalid_key"),
])
def test_config_validation(tmp_path, users, comm, code):
    with pytest.raises(snmp_config.SnmpConfigError) as exc:
        snmp_config.save(tmp_path, KEY, comm, users)
    assert exc.value.code == code


def test_trap_event_mapping():
    ev = snmp_receiver.trap_event("10.0.0.5", [(snmp_receiver.SYS_UPTIME, "123"),
                                              (snmp_receiver.SNMP_TRAP_OID, "1.3.6.1.6.3.1.1.5.3"),
                                              ("1.3.6.1.2.1.2.2.1.1.7", "7")])
    assert ev["event"]["action"] == "port-down" and ev["observer"]["ip"] == "10.0.0.5"
    assert ev["observer"]["ingress"]["interface"]["name"] == "ifIndex 7" and ev["siem"]["category"] == "network"
    assert ev["snmp"]["trap_oid"] == "1.3.6.1.6.3.1.1.5.3" and len(ev["snmp"]["varbinds"]) == 1
    unknown = snmp_receiver.trap_event("10.0.0.5", [(snmp_receiver.SNMP_TRAP_OID, "1.3.6.1.4.1.6574.1")])
    assert unknown["event"]["action"] == "1.3.6.1.4.1.6574.1"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_receive_v2c_and_v3_end_to_end(tmp_path):
    pytest.importorskip("pysnmp")
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        NotificationType,
        ObjectIdentity,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        send_notification,
        usmAesCfb128Protocol,
        usmHMACSHAAuthProtocol,
    )
    snmp_config.save(tmp_path, KEY, ["public-comm1"], USERS)
    port, got = free_port(), []

    async def scenario():
        stop = asyncio.Event()
        task = asyncio.create_task(snmp_receiver.run(tmp_path, KEY, ("127.0.0.1", port), send=got.append, stop=stop))
        await asyncio.sleep(1.0)
        target = await UdpTransportTarget.create(("127.0.0.1", port))
        # v2c als Trap; v3 als Inform (Empfänger ist autoritativ, Engine-ID-Erkennung ohne Vorkonfiguration)
        for auth, kind in ((CommunityData("public-comm1", mpModel=1), "trap"),  # noqa: S508 – v2c ist hier der Testgegenstand
                           (UsmUserData("siem", "authpass123", "privpass123", authProtocol=usmHMACSHAAuthProtocol,
                                        privProtocol=usmAesCfb128Protocol), "inform")):
            err = await send_notification(SnmpEngine(), auth, target, ContextData(), kind,
                                          NotificationType(ObjectIdentity("1.3.6.1.6.3.1.1.5.3")))
            assert not err[0], err
        for _ in range(30):
            if len(got) >= 2:
                break
            await asyncio.sleep(0.2)
        stop.set()
        await task

    asyncio.run(asyncio.wait_for(scenario(), 40))
    assert len(got) == 2 and {g["snmp"]["version"] for g in got} == {"v2c", "v3"}
    assert all(g["event"]["action"] == "port-down" and g["observer"]["ip"] == "127.0.0.1" for g in got)


def test_api_never_returns_keys_and_needs_write(h, settings):
    h.create_user("adm", ["system-admin"])
    h.create_user("aud", ["auditor"])
    c = h.login("adm")
    body = {"communities": ["public-comm1"], "v3_users": [dict(USERS[0])]}
    r = c.put("/api/snmp", json=body)
    assert r.status_code == 200 and "authpass123" not in r.text and r.json()["communities"] == 1
    assert c.put("/api/snmp", json={"v3_users": [dict(USERS[0], user="a b")]}).json()["detail"]["error"] == "snmp_invalid_user"
    assert h.login("aud").get("/api/snmp").status_code == 200
    assert h.login("aud").put("/api/snmp", json=body).status_code == 403
