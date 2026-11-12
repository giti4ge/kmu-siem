"""Unit-Tests für siem-hostd (nur Standardbibliothek).

Aufruf: python -m unittest discover -s tests/hostd -v
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "host" / "siem-hostd"))

import hostd  # noqa: E402


class FakeNft:
    """Ersetzt nft: zeichnet Aufrufe auf, kann Fehler simulieren."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.fail_check = False
        self.lock = threading.Lock()

    def __call__(self, args: list[str], stdin: str | None = None) -> None:
        with self.lock:
            if self.fail_check and args[:1] == ["-c"]:
                raise hostd.HostdError("Syntaxfehler (simuliert)")
            self.calls.append((args, stdin))

    def loaded(self) -> list[str]:
        """Tatsächlich geladene Konfigurationen (nft -f -)."""
        return [s or "" for a, s in self.calls if a == ["-f", "-"]]


def cfg(**services: list[str]) -> dict:
    return {"services": {n: {"sources": s} for n, s in services.items()}}


class TmpEnv(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.data = base / "data"
        self.nft_conf = base / "nftables.conf"
        hostd.AUDIT_LOG = base / "audit.log"
        self.nft = FakeNft()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def manager(self, timeout: int = 60) -> hostd.FirewallManager:
        return hostd.FirewallManager(self.data, self.nft_conf, self.nft, timeout)


# --------------------------------------------------------------------------- #
class TestValidation(unittest.TestCase):
    def test_normalize_dedupe_and_collapse(self) -> None:
        out = hostd.normalize_sources(["10.0.0.0/8", "10.1.2.3", "10.0.0.0/8", "192.168.1.5/24", "fe80::1/10"])
        self.assertEqual(out, ["10.0.0.0/8", "192.168.1.0/24", "fe80::/10"])

    def test_single_host(self) -> None:
        self.assertEqual(hostd.normalize_sources(["10.0.2.2"]), ["10.0.2.2/32"])

    def test_invalid_entries(self) -> None:
        for bad in (["10.0.0.0/33"], ["abc"], [""], [123], ["10.0.0.1; drop"], "10.0.0.0/8", [None]):
            with self.subTest(bad=bad), self.assertRaises(hostd.HostdError):
                hostd.normalize_sources(bad)

    def test_too_many(self) -> None:
        with self.assertRaises(hostd.HostdError):
            hostd.normalize_sources([f"10.0.{i // 256}.{i % 256}" for i in range(hostd.MAX_SOURCES + 1)])

    def test_validate_config(self) -> None:
        c = hostd.validate_config(cfg(ssh=["10.0.0.0/8"]))
        self.assertEqual(set(c["services"]), set(hostd.SERVICES))
        self.assertEqual(c["services"]["ssh"]["sources"], ["10.0.0.0/8"])
        self.assertEqual(c["services"]["https"]["sources"], [])

    def test_validate_rejects_unknown_service_and_fields(self) -> None:
        with self.assertRaises(hostd.HostdError):
            hostd.validate_config(cfg(telnet=["10.0.0.0/8"]))
        with self.assertRaises(hostd.HostdError):
            hostd.validate_config({"services": {"ssh": {"sources": [], "ports": [23]}}})
        with self.assertRaises(hostd.HostdError):
            hostd.validate_config({"services": []})
        with self.assertRaises(hostd.HostdError):
            hostd.validate_config("x")

    def test_defaults(self) -> None:
        d = hostd.default_config()
        self.assertIn("10.0.0.0/8", d["services"]["ssh"]["sources"])
        self.assertIn("fc00::/7", d["services"]["https"]["sources"])
        self.assertEqual(d["services"]["wef_https"]["sources"], [])


class TestRender(unittest.TestCase):
    def test_structure(self) -> None:
        text = hostd.render_nft(hostd.default_config())
        self.assertIn("table inet siem\ndelete table inet siem\n", text)
        self.assertNotIn("flush ruleset", text)
        self.assertIn("policy drop", text)
        self.assertIn('iifname "br-siem" oifname != "br-siem" accept', text)
        self.assertIn("set allow_ssh { type ipv4_addr; flags interval; auto-merge; elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }; }", text)
        self.assertIn("set allow_wef_https { type ipv4_addr; flags interval; auto-merge; }", text)
        self.assertIn("tcp dport 22 ip saddr @allow_ssh ct state new limit rate 30/minute", text)
        self.assertIn("udp dport 514 ip saddr @allow_syslog accept", text)
        self.assertIn("tcp dport 514 ip saddr @allow_syslog accept", text)
        self.assertIn("udp dport 162 ip6 saddr @allow_snmptrap6 accept", text)

    def test_deterministic(self) -> None:
        a = hostd.render_nft(hostd.validate_config(cfg(ssh=["192.168.0.0/16", "10.0.0.0/8"])))
        b = hostd.render_nft(hostd.validate_config(cfg(ssh=["10.0.0.0/8", "192.168.0.0/16"])))
        self.assertEqual(a, b)

    def test_v6_split(self) -> None:
        text = hostd.render_nft(hostd.validate_config(cfg(https=["10.0.0.0/8", "fd00::/8"])))
        self.assertIn("set allow_https { type ipv4_addr; flags interval; auto-merge; elements = { 10.0.0.0/8 }; }", text)
        self.assertIn("set allow_https6 { type ipv6_addr; flags interval; auto-merge; elements = { fd00::/8 }; }", text)


# --------------------------------------------------------------------------- #
class TestFirewallManager(TmpEnv):
    def test_apply_activates_but_does_not_persist(self) -> None:
        fw = self.manager()
        res = fw.apply(cfg(ssh=["10.0.0.0/8"], https=[]), actor="t")
        self.assertIn("token", res)
        self.assertEqual(res["timeout"], 60)
        self.assertEqual(len(self.nft.loaded()), 1)          # geladen
        self.assertFalse(self.nft_conf.exists())            # aber nicht dauerhaft
        self.assertIsNotNone(fw.show()["pending"])
        fw.rollback()

    def test_confirm_persists(self) -> None:
        fw = self.manager()
        token = fw.apply(cfg(ssh=["10.0.0.0/8"]))["token"]
        fw.confirm(token)
        self.assertTrue(self.nft_conf.exists())
        self.assertIsNone(fw.show()["pending"])
        self.assertEqual(fw.committed()["services"]["ssh"]["sources"], ["10.0.0.0/8"])
        self.assertEqual(self.nft_conf.read_text(encoding="utf-8"), hostd.render_nft(fw.committed()))
        if os.name == "posix":
            self.assertEqual(self.nft_conf.stat().st_mode & 0o777, 0o600)

    def test_wrong_token_rejected(self) -> None:
        fw = self.manager()
        fw.apply(cfg(ssh=["10.0.0.0/8"]))
        with self.assertRaises(hostd.HostdError):
            fw.confirm("falsch")
        self.assertIsNotNone(fw.show()["pending"])
        fw.rollback()

    def test_second_apply_while_pending_rejected(self) -> None:
        fw = self.manager()
        fw.apply(cfg(ssh=["10.0.0.0/8"]))
        with self.assertRaises(hostd.HostdError):
            fw.apply(cfg(ssh=["192.168.0.0/16"]))
        fw.rollback()

    def test_manual_rollback_restores_previous(self) -> None:
        fw = self.manager()
        before = fw.committed()
        fw.apply(cfg(ssh=["10.9.9.9"]))
        self.assertTrue(fw.rollback()["rolled_back"])
        self.assertEqual(self.nft.loaded()[-1], hostd.render_nft(before))
        self.assertIsNone(fw.show()["pending"])
        self.assertFalse(fw.rollback()["rolled_back"])

    def test_dead_mans_switch_expires(self) -> None:
        fw = self.manager()
        before = fw.committed()
        fw.apply(cfg(ssh=["10.9.9.9"]), timeout=10)
        fw._schedule(0.2)  # Frist für den Test verkürzen
        deadline = time.time() + 5
        while fw.show()["pending"] is not None and time.time() < deadline:
            time.sleep(0.05)
        self.assertIsNone(fw.show()["pending"])
        self.assertEqual(self.nft.loaded()[-1], hostd.render_nft(before))
        log_text = hostd.AUDIT_LOG.read_text(encoding="utf-8")
        self.assertIn("Dead-Man", log_text)

    def test_resume_after_restart_expired(self) -> None:
        fw = self.manager()
        before = fw.committed()
        fw.apply(cfg(ssh=["10.9.9.9"]))
        fw._cancel_timer()
        # Neustart simulieren: Frist bereits abgelaufen
        pend = json.loads((self.data / "firewall.pending.json").read_text())
        pend["deadline"] = time.time() - 1
        (self.data / "firewall.pending.json").write_text(json.dumps(pend))
        fw2 = self.manager()
        fw2.resume()
        self.assertIsNone(fw2.show()["pending"])
        self.assertEqual(self.nft.loaded()[-1], hostd.render_nft(before))

    def test_resume_after_restart_reschedules(self) -> None:
        fw = self.manager()
        fw.apply(cfg(ssh=["10.9.9.9"]))
        fw._cancel_timer()
        fw2 = self.manager()
        fw2.resume()
        self.assertIsNotNone(fw2._timer)
        self.assertGreater(fw2.show()["pending"]["seconds_left"], 50)
        fw2.rollback()

    def test_check_failure_changes_nothing(self) -> None:
        fw = self.manager()
        self.nft.fail_check = True
        with self.assertRaises(hostd.HostdError):
            fw.apply(cfg(ssh=["10.0.0.0/8"]))
        self.assertEqual(self.nft.loaded(), [])
        self.assertIsNone(fw.show()["pending"])

    def test_timeout_bounds(self) -> None:
        fw = self.manager()
        for t in (5, 601):
            with self.subTest(t=t), self.assertRaises(hostd.HostdError):
                fw.apply(cfg(ssh=["10.0.0.0/8"]), timeout=t)

    def test_init_adds_ssh_sources_idempotent(self) -> None:
        fw = self.manager()
        fw.init(["203.0.113.7"])
        first = self.nft_conf.read_text(encoding="utf-8")
        self.assertIn("203.0.113.7/32", fw.committed()["services"]["ssh"]["sources"])
        fw.init(["203.0.113.7", "10.0.2.2"])  # 10.0.2.2 liegt in 10.0.0.0/8
        self.assertEqual(self.nft_conf.read_text(encoding="utf-8"), first)

    def test_init_refuses_while_pending(self) -> None:
        fw = self.manager()
        fw.apply(cfg(ssh=["10.0.0.0/8"]))
        with self.assertRaises(hostd.HostdError):
            fw.init([])
        fw.rollback()


# --------------------------------------------------------------------------- #
class TestDispatcher(TmpEnv):
    def setUp(self) -> None:
        super().setUp()
        self.d = hostd.Dispatcher(self.manager(), status=lambda: {"version": "test"})

    def test_status(self) -> None:
        self.assertEqual(self.d.handle({"action": "system.status"}), {"ok": True, "result": {"version": "test"}})

    def test_unknown_action(self) -> None:
        r = self.d.handle({"action": "shell.exec", "params": {"cmd": "id"}})
        self.assertFalse(r["ok"])
        self.assertIn("Unbekannte Aktion", r["error"])

    def test_bad_requests(self) -> None:
        self.assertFalse(self.d.handle([])["ok"])
        self.assertFalse(self.d.handle({"action": "firewall.show", "params": []})["ok"])
        self.assertFalse(self.d.handle({"action": "firewall.show", "actor": "x" * 200})["ok"])

    def test_validation_error_reported(self) -> None:
        r = self.d.handle({"action": "firewall.apply", "params": {"config": cfg(ssh=["kaputt"])}})
        self.assertFalse(r["ok"])
        self.assertIn("Ungültig", r["error"])

    def test_apply_confirm_roundtrip(self) -> None:
        r = self.d.handle({"action": "firewall.apply", "params": {"config": cfg(ssh=["10.0.0.0/8"])}, "actor": "web"})
        self.assertTrue(r["ok"])
        r2 = self.d.handle({"action": "firewall.confirm", "params": {"token": r["result"]["token"]}})
        self.assertEqual(r2, {"ok": True, "result": {"committed": True}})


@unittest.skipUnless(hasattr(socket, "AF_UNIX") and os.name == "posix", "Unix-Sockets nur unter Linux")
class TestSocketServer(TmpEnv):
    def setUp(self) -> None:
        super().setUp()
        self.sock_path = Path(self.tmp.name) / "hostd.sock"
        hostd.SOCKET_PATH = self.sock_path
        self.server = hostd.HostdServer(self.sock_path, hostd.Dispatcher(self.manager(), status=lambda: {"v": 1}))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def raw(self, data: bytes) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(str(self.sock_path))
            s.sendall(data)
            return json.loads(s.makefile().readline())

    def test_call(self) -> None:
        self.assertEqual(hostd.call("system.status"), {"ok": True, "result": {"v": 1}})

    def test_socket_permissions(self) -> None:
        self.assertIn(self.sock_path.stat().st_mode & 0o777, (0o600, 0o660))

    def test_invalid_json(self) -> None:
        self.assertEqual(self.raw(b"kein json\n"), {"ok": False, "error": "Ungültiges JSON"})

    def test_too_large(self) -> None:
        self.assertEqual(self.raw(b"x" * (hostd.MAX_MESSAGE + 10) + b"\n")["error"], "Anfrage zu groß")


if __name__ == "__main__":
    unittest.main()
