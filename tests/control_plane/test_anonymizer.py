"""Pseudonymisierung: keine Klartext-IPs/MACs/E-Mail/Hostnamen/Benutzer in Proben aller Parser-Fixtures."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from siem_api.anonymizer import Pseudonymizer

ROOT = Path(__file__).resolve().parents[2]
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _fixtures() -> list[dict]:
    out = []
    for f in sorted((ROOT / "app" / "vector" / "tests").glob("*.yaml")):
        for t in yaml.safe_load(f.read_text("utf-8")).get("tests", []):
            for i in t.get("inputs", []):
                lf = i.get("log_fields") or {}
                if lf.get("message"):
                    out.append(lf)
    return out


def test_fixtures_have_no_cleartext(tmp_path):
    rows = _fixtures()
    assert len(rows) > 20
    hosts = sorted({str(r["hostname"]) for r in rows if r.get("hostname")})
    p = Pseudonymizer(tmp_path / "p.json", hosts)
    for r in rows:
        original = f'{r.get("hostname", "")} {r["message"]}'
        out = p.line(original)
        for ip in IPV4.findall(original):
            if all(int(x) < 256 for x in ip.split(".")):
                assert ip not in out, (ip, out)
        for h in hosts:
            assert not re.search(r"(?<![\w-])" + re.escape(h) + r"(?![\w-])", out, re.I), (h, out)
        assert not re.search(r"(?i)[0-9a-f]{2}(:[0-9a-f]{2}){5}", re.sub(r"\b02:00:00(:[0-9a-f]{2}){3}\b", "", out)), out


def test_consistent_and_formats(tmp_path):
    p = Pseudonymizer(tmp_path / "p.json", ["fw-main"], ["mueller"])
    a = p.line("Nov 13 10:00:01 fw-main sshd[1]: Failed password for mueller from 192.168.1.50 port 22 ssh2")
    b = p.line("Accepted publickey for mueller from 192.168.1.50 mac aa:bb:cc:dd:ee:ff mail hans.meier@firma.at")
    assert "mueller" not in a + b and "192.168.1.50" not in a + b and "firma.at" not in b and "aa:bb:cc" not in b
    ip = re.search(r"from (\S+) port", a).group(1)
    assert ip in b  # konsistent
    assert "sshd[1]: Failed password for USER_" in a
    # Zuordnung bleibt lokal und ist umkehrbar
    assert p.reveal(ip) == "192.168.1.50"
    p.save()
    assert (tmp_path / "p.json").exists()
    p2 = Pseudonymizer(tmp_path / "p.json")
    assert p2.line("src 192.168.1.50") == f"src {ip}"


def test_keeps_non_sensitive(tmp_path):
    p = Pseudonymizer(tmp_path / "p.json")
    s = "version 1.2.3 build 10.2 level=notice user=root"
    assert p.line(s) == s
