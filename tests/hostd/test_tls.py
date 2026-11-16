"""Web-Zertifikat: Validierung, Einspielen mit Sicherung, Rückfall bei ungesundem Proxy, Reset."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "host" / "siem-hostd"))

import hostd  # noqa: E402

OPENSSL = shutil.which("openssl")


def make_pair(d: Path, cn: str, days: int = 30) -> tuple[str, str]:
    key, crt = d / f"{cn}.key", d / f"{cn}.crt"
    subprocess.run([OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-days", str(days), "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}"],
                   check=True, capture_output=True)
    k = subprocess.run([OPENSSL, "pkey", "-in", str(key)], check=True, capture_output=True, text=True).stdout
    return crt.read_text(), k


@unittest.skipUnless(OPENSSL, "openssl fehlt")
class WebCertificateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        hostd.OPENSSL = OPENSSL
        self.pki = self.dir / "pki"
        (self.pki / "proxy").mkdir(parents=True)
        self.orig_crt, self.orig_key = make_pair(self.dir, "intern.local")
        for n, v in (("web.chain.crt", self.orig_crt), ("web.key", self.orig_key)):
            (self.pki / n).write_text(v)
        (self.pki / "proxy" / "web.crt").write_text(self.orig_crt)
        (self.pki / "proxy" / "web.key").write_text(self.orig_key)
        self.restarts = 0
        self.ok = True

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def cert(self) -> hostd.WebCertificate:
        def restart() -> None:
            self.restarts += 1
        return hostd.WebCertificate(self.pki, restart=restart, healthy=lambda: self.ok, delay=0)

    def wait(self, c: hostd.WebCertificate) -> dict:
        for _ in range(100):
            last = c.status().get("last")
            if last:
                return last
            time.sleep(0.05)
        self.fail("kein Ergebnis")

    def test_install_and_status(self) -> None:
        c = self.cert()
        crt, key = make_pair(self.dir, "siem.firma.at")
        r = c.install({"chain_pem": crt, "key_pem": key}, "admin")
        self.assertTrue(r["scheduled"])
        self.assertIn("siem.firma.at", r["subject"])
        self.assertTrue(self.wait(c)["ok"])
        st = c.status()
        self.assertTrue(st["custom"] and st["has_backup"])
        self.assertEqual((self.pki / "proxy" / "web.crt").read_text(), crt)
        self.assertEqual((self.pki / "web.custom").read_text(), "admin")
        self.assertEqual(self.restarts, 1)

    def test_key_mismatch_rejected(self) -> None:
        c = self.cert()
        crt, _ = make_pair(self.dir, "a.local")
        _, other = make_pair(self.dir, "b.local")
        with self.assertRaises(hostd.HostdError):
            c.install({"chain_pem": crt, "key_pem": other}, "x")
        self.assertEqual((self.pki / "proxy" / "web.crt").read_text(), self.orig_crt)
        self.assertEqual(self.restarts, 0)

    def test_garbage_rejected(self) -> None:
        c = self.cert()
        for p in ({}, {"chain_pem": "x", "key_pem": "y"}, {"chain_pem": 1, "key_pem": 2}):
            with self.assertRaises(hostd.HostdError):
                c.install(p, "x")

    def test_unhealthy_proxy_rolls_back(self) -> None:
        c = self.cert()
        self.ok = False
        crt, key = make_pair(self.dir, "neu.local")
        c.install({"chain_pem": crt, "key_pem": key}, "x")
        last = self.wait(c)
        self.assertFalse(last["ok"])
        self.assertIn("wiederhergestellt", last["error"])
        self.assertEqual((self.pki / "proxy" / "web.crt").read_text(), self.orig_crt)
        self.assertFalse((self.pki / "web.custom").exists())
        self.assertEqual(self.restarts, 2)

    def test_rollback_and_reset(self) -> None:
        c = self.cert()
        crt1, key1 = make_pair(self.dir, "eins.local")
        crt2, key2 = make_pair(self.dir, "zwei.local")
        c.install({"chain_pem": crt1, "key_pem": key1}, "x")
        self.wait(c)
        (self.pki / "web.last.json").unlink()
        c.install({"chain_pem": crt2, "key_pem": key2}, "x")
        self.wait(c)
        (self.pki / "web.last.json").unlink()
        c.rollback("x")
        self.wait(c)
        self.assertEqual((self.pki / "proxy" / "web.crt").read_text(), crt1)
        (self.pki / "web.last.json").unlink()
        c.rollback("x", reset=True)
        self.wait(c)
        self.assertEqual((self.pki / "proxy" / "web.crt").read_text(), self.orig_crt)
        self.assertFalse(c.status()["custom"])

    def test_dispatch_registered(self) -> None:
        d = hostd.Dispatcher(hostd.FirewallManager.__new__(hostd.FirewallManager), status=lambda: {})
        self.assertIn("tls.install", d.actions)
        self.assertIn("tls.reset", d.actions)


if __name__ == "__main__":
    unittest.main()
