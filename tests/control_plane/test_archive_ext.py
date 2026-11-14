"""Archiv-Erweiterungen: RFC-3161-Zeitstempel, Replikation (Verzeichnis, S3), Löschsperre bis zur Replikation."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_archive import T0, arch, make  # noqa: F401 – Fixture und Hilfsfunktion

from siem_api import archive as ar
from siem_api import archive_ext as ax


def _fake_tsa_response(digest: bytes, nonce: int, status: int = 0) -> bytes:
    token = ax._tlv(0x30, ax._tlv(0x04, digest) + ax._int(nonce))
    return ax._tlv(0x30, ax._tlv(0x30, ax._int(status)) + token)


def test_tsa_request_and_response_checks() -> None:
    d = bytes(range(32))
    req = ax.build_request(d, 12345)
    assert req[0] == 0x30 and d in req and req.endswith(b"\x01\x01\xff")
    ax.check_response(_fake_tsa_response(d, 12345), d, 12345)
    with pytest.raises(ValueError, match="tsa_rejected"):
        ax.check_response(_fake_tsa_response(d, 12345, status=2), d, 12345)
    with pytest.raises(ValueError, match="tsa_mismatch"):
        ax.check_response(_fake_tsa_response(bytes(32), 12345), d, 12345)
    with pytest.raises(ValueError, match="tsa_bad_response"):
        ax.check_response(b"\x00\x01", d, 12345)


def test_stamp_all_and_verify(arch: ar.Archive, tmp_path: Path, monkeypatch) -> None:  # noqa: F811
    make(arch.root, "firewall", "07", [{"a": 1}])
    arch.seal()
    cfg = ax.Config(tmp_path / "t.json", bytes(32))
    cfg.save("https://tsa.example/ts", {"type": "none"}, None)
    monkeypatch.setattr(ax, "request_timestamp", lambda url, dig: (_fake_tsa_response(dig, 7), 7))
    assert ax.stamp_all(arch, cfg)["stamped"] == 1
    assert ax.stamp_all(arch, cfg)["stamped"] == 0  # unverändert
    assert ax.verify_stamps(arch) == []
    log = arch.root / "_seals" / "tsa" / "firewall.jsonl"
    rec = json.loads(log.read_text())
    rec["chain"] = "0" * 64
    log.write_text(json.dumps(rec) + "\n")
    assert ax.verify_stamps(arch)[0]["problem"] in ("tsa_invalid", "tsa_unbound")
    assert arch.verify()["ok"]  # Zeitstempel-Verzeichnis zählt nicht als Kategorie


def test_config_validation(tmp_path: Path) -> None:
    cfg = ax.Config(tmp_path / "t.json", bytes(32))
    with pytest.raises(ValueError):
        cfg.save("ftp://x", {"type": "none"}, None)
    with pytest.raises(ValueError):
        cfg.save("", {"type": "dir", "subdir": "../x"}, None)
    with pytest.raises(ValueError):
        cfg.save("", {"type": "s3", "endpoint": "https://s3.example", "bucket": "B!"}, None)
    s3 = {"type": "s3", "endpoint": "https://s3.example", "bucket": "siem-archiv", "access_key": "AK", "lock_days": 30}
    v = cfg.save("", s3, "geheim")
    assert v["target"]["has_secret"] and "secret_key" not in v["target"] and cfg.secret() == "geheim"
    cfg.save("", {**s3, "lock_days": 0}, None)
    assert cfg.secret() == "geheim"  # Geheimnis bleibt bei Änderung ohne neuen Wert


def test_replication_dir_and_prune_gate(arch: ar.Archive, tmp_path: Path) -> None:  # noqa: F811
    make(arch.root, "firewall", "05", [{"a": 1}])
    arch.seal()
    cfg = ax.Config(tmp_path / "t.json", bytes(32))
    cfg.save("", {"type": "dir", "subdir": "siem"}, None)
    rep = ax.Replicator(arch, cfg, tmp_path / "lt", tmp_path / "repl.txt")
    arch.clock.now = T0 + timedelta(days=40)
    assert arch.prune({}, 30, rep.is_replicated) == {"pruned": 0}  # Ziel aktiv, noch nicht repliziert
    assert rep.run() == {"replicated": 1, "failed": 0, "enabled": True, "error": ""}
    assert (tmp_path / "lt/siem/firewall/2026/11/14/05.jsonl.gz").is_file()
    assert (tmp_path / "lt/siem/_seals/firewall.jsonl").is_file()
    assert rep.run()["replicated"] == 0
    assert arch.prune({}, 30, rep.is_replicated) == {"pruned": 1}


def test_s3_replication_and_etag_check(arch: ar.Archive, tmp_path: Path) -> None:  # noqa: F811
    make(arch.root, "firewall", "05", [{"a": 1}])
    arch.seal()
    seen: list = []

    def fake_put(t, secret, key, data):
        seen.append((t["lock_days"], secret, key))
        return hashlib.md5(data).hexdigest()  # noqa: S324

    cfg = ax.Config(tmp_path / "t.json", bytes(32))
    cfg.save("", {"type": "s3", "endpoint": "https://s3.example", "bucket": "siem-archiv", "access_key": "AK",
                  "lock_days": 30, "prefix": "kunde1"}, "sek")
    rep = ax.Replicator(arch, cfg, tmp_path / "lt", tmp_path / "repl.txt", s3=fake_put)
    assert rep.run()["replicated"] == 1
    assert seen[0] == (30, "sek", "kunde1/firewall/2026/11/14/05.jsonl.gz")
    rep.s3 = lambda *a: "deadbeef"
    (tmp_path / "repl.txt").unlink()
    assert rep.run()["failed"] >= 1


def test_s3_signature_shape() -> None:
    captured = {}

    class R:
        headers = {"ETag": '"abc"'}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout):
        captured["req"] = req
        return R()

    t = {"endpoint": "https://s3.example", "bucket": "b", "region": "eu-1", "access_key": "AK", "lock_days": 7,
         "lock_mode": "COMPLIANCE"}
    assert ax.s3_put(t, "sek", "k/x.gz", b"data", now=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), opener=opener) == "abc"
    h = {k.lower(): v for k, v in captured["req"].header_items()}
    assert h["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AK/20260102/eu-1/s3/aws4_request")
    assert h["x-amz-object-lock-mode"] == "COMPLIANCE"
    assert h["x-amz-object-lock-retain-until-date"] == "2026-01-09T03:04:05Z"
    assert "content-md5" in h
