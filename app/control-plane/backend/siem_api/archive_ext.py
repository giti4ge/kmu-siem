"""Archiv-Erweiterungen (Spec 4.14a): RFC-3161-Zeitstempel und Replikation auf ein Langzeitziel.

* **Zeitstempel:** Täglich wird der aktuelle Kettenwert (SHA-256) je Kategorie bei einer konfigurierbaren
  Zeitstempelautorität (TSA, RFC 3161) angefragt. Die Antwort (Token) wird unverändert abgelegt
  (``_seals/tsa/<kategorie>.jsonl``). Die App prüft Status, Bindung an den Kettenwert und die Nonce; die
  vollständige Zertifikatsprüfung erfolgt unabhängig mit ``openssl ts -verify`` (Token ist exportierbar).
* **Langzeitziel:** ``dir`` (ein auf dem Host eingehängtes Verzeichnis, z. B. NFS/SMB unter ``/opt/siem/data/longterm``)
  oder ``s3`` (S3-kompatibel, optional mit Object Lock/WORM). Jede Datei wird nach dem Kopieren verifiziert
  (Hash bzw. ETag); erst danach darf die lokale Retention sie löschen.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .archive import SEALS_DIR, Archive, sha256_file
from .security import crypto

CONTEXT = "archive.target"
MAX_UPLOAD = 512 * 1024 * 1024
_HOST = re.compile(r"^[A-Za-z0-9.-]+(:\d{1,5})?$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
SHA256_OID = bytes.fromhex("0609608648016503040201")


# ---------------------------------------------------------------- RFC 3161 (minimales DER)
def _tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 128:
        head = bytes([tag, n])
    else:
        lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(lb)]) + lb
    return head + content


def _int(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return _tlv(0x02, b)


def build_request(digest: bytes, nonce: int) -> bytes:
    """TimeStampReq (SHA-256, certReq=TRUE)."""
    imprint = _tlv(0x30, _tlv(0x30, SHA256_OID + b"\x05\x00") + _tlv(0x04, digest))
    return _tlv(0x30, _int(1) + imprint + _int(nonce) + _tlv(0x01, b"\xff"))


def _read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    tag = data[pos]
    ln = data[pos + 1]
    pos += 2
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + k], "big")
        pos += k
    if pos + ln > len(data):
        raise ValueError("DER abgeschnitten")
    return tag, data[pos:pos + ln], pos + ln


def check_response(resp: bytes, digest: bytes, nonce: int) -> None:
    """Status ``granted`` (0/1), Token enthält Digest und Nonce; sonst ValueError."""
    try:
        tag, body, _ = _read_tlv(resp, 0)
        if tag != 0x30:
            raise ValueError("kein TimeStampResp")
        t2, status_info, nxt = _read_tlv(body, 0)
        _t3, status_int, _ = _read_tlv(status_info, 0)
        if t2 != 0x30 or int.from_bytes(status_int, "big") not in (0, 1):
            raise ValueError("tsa_rejected")
        if nxt >= len(body):
            raise ValueError("tsa_no_token")
    except (IndexError, ValueError) as exc:
        raise ValueError(str(exc) if str(exc).startswith("tsa_") else "tsa_bad_response") from None
    if digest not in resp or _int(nonce)[2:] not in resp:
        raise ValueError("tsa_mismatch")


def request_timestamp(url: str, digest: bytes, timeout: float = 20.0) -> tuple[bytes, int]:
    nonce = secrets.randbits(63)
    req = urllib.request.Request(url, data=build_request(digest, nonce), method="POST",  # noqa: S310 – https/http vom Admin
                                 headers={"Content-Type": "application/timestamp-query"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            resp = r.read(1 << 20)
    except (OSError, urllib.error.URLError) as exc:
        raise ValueError("tsa_unreachable") from exc
    check_response(resp, digest, nonce)
    return resp, nonce


# ---------------------------------------------------------------- Konfiguration
class Config:
    def __init__(self, path: Path, master_key: bytes) -> None:
        self.path = path
        self.key = master_key

    def _raw(self) -> dict[str, Any]:
        try:
            d = json.loads(self.path.read_text("utf-8"))
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def view(self) -> dict[str, Any]:
        d = self._raw()
        t = d.get("target", {"type": "none"})
        return {"tsa_url": d.get("tsa_url", ""),
                "target": {k: v for k, v in t.items() if k != "secret_key"} | {"has_secret": bool(t.get("secret_key"))}}

    def secret(self) -> str:
        blob = self._raw().get("target", {}).get("secret_key")
        return crypto.decrypt(self.key, base64.b64decode(blob), CONTEXT) if blob else ""

    def save(self, tsa_url: str, target: dict[str, Any], secret_key: str | None) -> dict[str, Any]:
        if tsa_url and not re.match(r"^https?://[^\s/]+(/\S*)?$", tsa_url):
            raise ValueError("archive_bad_tsa")
        old = self._raw().get("target", {})
        t: dict[str, Any] = {"type": target.get("type", "none")}
        if t["type"] == "dir":
            sub = str(target.get("subdir", "")).strip("/")
            if sub and not re.match(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$", sub) or ".." in sub:
                raise ValueError("archive_bad_target")
            t["subdir"] = sub
        elif t["type"] == "s3":
            ep, bucket = str(target.get("endpoint", "")), str(target.get("bucket", ""))
            if not re.match(r"^https?://", ep) or not _HOST.match(ep.split("://", 1)[1].rstrip("/")) \
                    or not _BUCKET.match(bucket):
                raise ValueError("archive_bad_target")
            lock = target.get("lock_days")
            t.update(endpoint=ep.rstrip("/"), bucket=bucket, region=str(target.get("region") or "us-east-1"),
                     access_key=str(target.get("access_key", ""))[:128],
                     prefix=str(target.get("prefix", "")).strip("/"),
                     lock_days=int(lock) if lock else 0, lock_mode=target.get("lock_mode", "COMPLIANCE"))
            if t["lock_mode"] not in ("COMPLIANCE", "GOVERNANCE") or not 0 <= t["lock_days"] <= 3650:
                raise ValueError("archive_bad_target")
            if secret_key:
                t["secret_key"] = base64.b64encode(crypto.encrypt(self.key, secret_key, CONTEXT)).decode()
            elif old.get("secret_key"):
                t["secret_key"] = old["secret_key"]
        elif t["type"] != "none":
            raise ValueError("archive_bad_target")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"tsa_url": tsa_url, "target": t}), "utf-8")
        os.replace(tmp, self.path)
        return self.view()

    def target(self) -> dict[str, Any]:
        return self._raw().get("target", {"type": "none"})

    def tsa_url(self) -> str:
        return str(self._raw().get("tsa_url", ""))


# ---------------------------------------------------------------- S3 (SigV4, nur Standardbibliothek)
def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def s3_put(t: dict[str, Any], secret: str, key: str, data: bytes, now: datetime | None = None,
           opener: Callable[..., Any] = urllib.request.urlopen) -> str:
    """PUT-Objekt; Rückgabe ETag (ohne Anführungszeichen). Object-Lock-Header, wenn ``lock_days`` > 0."""
    now = now or datetime.now(UTC)
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    host = t["endpoint"].split("://", 1)[1]
    path = "/" + urllib.parse.quote(f"{t['bucket']}/{key}", safe="/-_.~")
    md5 = base64.b64encode(hashlib.md5(data, usedforsecurity=False).digest()).decode()
    headers = {"host": host, "x-amz-content-sha256": hashlib.sha256(data).hexdigest(), "x-amz-date": amz,
               "content-md5": md5}
    if t.get("lock_days"):
        until = (now + timedelta(days=int(t["lock_days"]))).strftime("%Y-%m-%dT%H:%M:%SZ")
        headers["x-amz-object-lock-mode"] = t.get("lock_mode", "COMPLIANCE")
        headers["x-amz-object-lock-retain-until-date"] = until
    names = sorted(headers)
    canon = "PUT\n" + path + "\n\n" + "".join(f"{n}:{headers[n]}\n" for n in names) + "\n" + ";".join(names) + "\n" \
        + headers["x-amz-content-sha256"]
    scope = f"{day}/{t['region']}/s3/aws4_request"
    sts = f"AWS4-HMAC-SHA256\n{amz}\n{scope}\n{hashlib.sha256(canon.encode()).hexdigest()}"
    k = _sign(_sign(_sign(_sign(("AWS4" + secret).encode(), day), t["region"]), "s3"), "aws4_request")
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={t['access_key']}/{scope}, SignedHeaders={';'.join(names)}, "
            f"Signature={sig}")
    req = urllib.request.Request(t["endpoint"] + path, data=data, method="PUT",  # noqa: S310
                                 headers={**{n: v for n, v in headers.items() if n != "host"}, "Authorization": auth})
    try:
        with opener(req, timeout=120) as r:
            etag = (r.headers.get("ETag") or "").strip('"')
    except (OSError, urllib.error.URLError) as exc:
        raise ValueError("replication_s3_failed") from exc
    return etag


# ---------------------------------------------------------------- Replikation
class Replicator:
    def __init__(self, archive: Archive, config: Config, longterm_dir: Path, state_path: Path,
                 s3: Callable[..., str] = s3_put) -> None:
        self.archive = archive
        self.config = config
        self.dir = longterm_dir
        self.path = state_path
        self.s3 = s3
        self.lock = threading.Lock()

    def done(self) -> set[str]:
        try:
            return {ln for ln in self.path.read_text("utf-8").splitlines() if ln}
        except OSError:
            return set()

    def is_replicated(self, cat: str, rel: str) -> bool:
        return f"{cat}/{rel}" in self.done()

    def enabled(self) -> bool:
        return self.config.target().get("type", "none") != "none"

    def _put(self, t: dict[str, Any], key: str, src: Path) -> None:
        if t["type"] == "dir":
            dst = self.dir / t.get("subdir", "") / key
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_name(dst.name + ".part")
            shutil.copyfile(src, tmp)
            if sha256_file(tmp)[0] != sha256_file(src)[0]:
                tmp.unlink(missing_ok=True)
                raise ValueError("replication_verify_failed")
            os.replace(tmp, dst)
        else:
            if src.stat().st_size > MAX_UPLOAD:
                raise ValueError("replication_too_large")
            data = src.read_bytes()
            full = "/".join(x for x in (t.get("prefix", ""), key) if x)
            etag = self.s3(t, self.config.secret(), full, data)
            if etag and etag != hashlib.md5(data, usedforsecurity=False).hexdigest():  # noqa: S324
                raise ValueError("replication_verify_failed")

    def run(self) -> dict[str, Any]:
        t = self.config.target()
        if t.get("type", "none") == "none":
            return {"replicated": 0, "failed": 0, "enabled": False}
        ok = bad = 0
        last = ""
        with self.lock:
            done = self.done()
            new: list[str] = []
            for cat in self.archive.categories():
                for x in self.archive.seals(cat):
                    if x.get("type") == "prune":
                        continue
                    ref = f"{cat}/{x['file']}"
                    src = self.archive.root / cat / x["file"]
                    if ref in done or not src.is_file():
                        continue
                    try:
                        self._put(t, ref, src)
                        new.append(ref)
                        ok += 1
                    except (ValueError, OSError) as exc:
                        bad += 1
                        last = str(exc)[:120]
                # Siegelprotokoll (wächst) und Zeitstempel immer mitführen
                for sub in (f"{cat}.jsonl", f"tsa/{cat}.jsonl"):
                    src = self.archive.root / SEALS_DIR / sub
                    if src.is_file():
                        try:
                            self._put(t, f"{SEALS_DIR}/{sub}", src)
                        except (ValueError, OSError) as exc:
                            bad += 1
                            last = str(exc)[:120]
            if new:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write("".join(n + "\n" for n in new))
        return {"replicated": ok, "failed": bad, "enabled": True, "error": last}


# ---------------------------------------------------------------- Zeitstempel je Kategorie
def stamp_all(archive: Archive, config: Config) -> dict[str, Any]:
    url = config.tsa_url()
    if not url:
        return {"stamped": 0, "enabled": False}
    n, err = 0, ""
    d = archive.root / SEALS_DIR / "tsa"
    for cat in archive.categories():
        seals = archive.seals(cat)
        if not seals:
            continue
        chain = seals[-1]["chain"]
        log = d / f"{cat}.jsonl"
        try:
            last = json.loads(log.read_text("utf-8").splitlines()[-1])["chain"]
        except (OSError, IndexError, ValueError, KeyError):
            last = ""
        if last == chain:
            continue
        try:
            token, nonce = request_timestamp(url, bytes.fromhex(chain))
        except ValueError as exc:
            err = str(exc)
            continue
        d.mkdir(mode=0o750, parents=True, exist_ok=True)
        rec = {"chain": chain, "seq": seals[-1]["seq"], "at": datetime.now(UTC).isoformat(timespec="seconds"),
               "tsa": url, "nonce": nonce, "token": base64.b64encode(token).decode()}
        with log.open("ab") as fh:
            fh.write(json.dumps(rec, sort_keys=True).encode() + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        n += 1
    return {"stamped": n, "enabled": True, "error": err}


def verify_stamps(archive: Archive) -> list[dict[str, Any]]:
    """Prüft, dass jeder Zeitstempel an einen Kettenwert des Siegelprotokolls gebunden ist."""
    problems: list[dict[str, Any]] = []
    d = archive.root / SEALS_DIR / "tsa"
    for log in sorted(d.glob("*.jsonl")) if d.is_dir() else []:
        cat = log.stem
        chains = {x["chain"] for x in archive.seals(cat)}
        for ln in log.read_text("utf-8").splitlines():
            try:
                r = json.loads(ln)
                check_response(base64.b64decode(r["token"]), bytes.fromhex(r["chain"]), int(r["nonce"]))
                if r["chain"] not in chains:
                    problems.append({"category": cat, "file": f"seq {r.get('seq')}", "problem": "tsa_unbound"})
            except (ValueError, KeyError, TypeError):
                problems.append({"category": cat, "file": "", "problem": "tsa_invalid"})
    return problems
