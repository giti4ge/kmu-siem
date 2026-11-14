"""Revisionssicheres Rohdaten-Archiv (Spec 4.14a, ADR-16): Versiegelung und Integritätsprüfung.

Vector schreibt jedes Ereignis in stündliche Dateien ``<kategorie>/YYYY/MM/DD/HH.jsonl.gz`` (Stunde der Aufnahme,
gzip statt zstd, weil die Prüfung mit der Python-Standardbibliothek laufen soll). Abgeschlossene Stunden werden
versiegelt: je Datei ein Eintrag im Siegelprotokoll ``_seals/<kategorie>.jsonl`` mit SHA-256, Größe, Verkettung
(``chain = SHA-256(prev|seq|datei|sha256|bytes|zeit)``) und Ed25519-Signatur über ``chain``. Wird eine Datei
verändert, gelöscht oder ein Siegel entfernt/umgestellt, erkennt die Prüfung das und benennt die Stelle.
Ein externer RFC-3161-Zeitstempel und die Replikation auf ein Langzeitziel sind noch nicht angebunden.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS = "0" * 64
GRACE = timedelta(minutes=10)  # Stunde gilt erst nach dieser Frist als abgeschlossen (und Datei muss ruhen)
SEAL_INTERVAL = 900
SEALS_DIR = "_seals"
_CAT = re.compile(r"^[a-z]+$")
_FILE = re.compile(r"^(\d{4})/(\d{2})/(\d{2})/(\d{2})\.jsonl\.gz$")


def load_or_create_key(path: Path) -> Ed25519PrivateKey:
    """Archiv-Signaturschlüssel (PEM, 0600) lesen; fehlt er, einmalig und exklusiv erzeugen."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        return serialization.load_pem_private_key(path.read_bytes(), password=None)  # type: ignore[return-value]
    except FileNotFoundError:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return load_or_create_key(path)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
            fh.flush()
            os.fsync(fh.fileno())
        return key


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _canon(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def _chain(prev: str, seq: int, file: str, sha: str, size: int, at: str) -> str:
    return hashlib.sha256(f"{prev}|{seq}|{file}|{sha}|{size}|{at}".encode()).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def slot_end(rel: str) -> datetime | None:
    """Ende der Archivstunde aus dem relativen Dateipfad (UTC); None bei fremdem Namen."""
    m = _FILE.match(rel)
    if not m:
        return None
    try:
        return datetime(*(int(x) for x in m.groups()), tzinfo=UTC) + timedelta(hours=1)
    except ValueError:
        return None


class Archive:
    def __init__(self, root: Path, key: Ed25519PrivateKey,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.root = root
        self.key = key
        self.pub = key.public_key()
        self.clock = clock
        self.lock = threading.Lock()

    # ---- Struktur ----
    def categories(self) -> list[str]:
        try:
            return sorted(p.name for p in self.root.iterdir() if p.is_dir() and _CAT.match(p.name))
        except OSError:
            return []

    def files(self, cat: str) -> list[str]:
        base = self.root / cat
        out: list[str] = []
        for p in base.rglob("*.jsonl.gz"):
            rel = p.relative_to(base).as_posix()
            if slot_end(rel):
                out.append(rel)
        return sorted(out)

    def _log(self, cat: str) -> Path:
        return self.root / SEALS_DIR / f"{cat}.jsonl"

    def seals(self, cat: str) -> list[dict[str, Any]]:
        try:
            lines = self._log(cat).read_text("utf-8").splitlines()
        except FileNotFoundError:
            return []
        out = []
        for ln in lines:
            if ln.strip():
                out.append(json.loads(ln))
        return out

    # ---- Versiegeln ----
    def seal(self) -> dict[str, Any]:
        """Alle abgeschlossenen, noch nicht versiegelten Dateien versiegeln (Reihenfolge: Stunde, Kategorie)."""
        sealed, skipped = 0, 0
        now = self.clock()
        with self.lock:
            for cat in self.categories():
                seals = self.seals(cat)
                done = {s["file"] for s in seals}
                prev = seals[-1]["chain"] if seals else GENESIS
                seq = seals[-1]["seq"] + 1 if seals else 1
                for rel in self.files(cat):
                    end = slot_end(rel)
                    path = self.root / cat / rel
                    if rel in done or end is None:
                        continue
                    if now < end + GRACE or now.timestamp() - path.stat().st_mtime < GRACE.total_seconds():
                        skipped += 1
                        continue
                    sha, size = sha256_file(path)
                    at = now.isoformat(timespec="seconds")
                    chain = _chain(prev, seq, rel, sha, size, at)
                    rec = {"seq": seq, "category": cat, "file": rel, "sha256": sha, "bytes": size, "prev": prev,
                           "sealed_at": at, "chain": chain, "sig": self.key.sign(chain.encode()).hex()}
                    self._append(cat, rec)
                    prev, seq, sealed = chain, seq + 1, sealed + 1
        return {"sealed": sealed, "waiting": skipped}

    def _append(self, cat: str, rec: dict[str, Any]) -> None:
        log = self._log(cat)
        log.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        with log.open("ab") as fh:
            fh.write(_canon(rec) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())

    # ---- Aufbewahrung ----
    def prune(self, days: dict[str, int], default: int,
              can_prune: Callable[[str, str], bool] | None = None) -> dict[str, Any]:
        """Versiegelte Dateien nach Ablauf der Archiv-Retention löschen; jede Löschung wird in der Kette vermerkt."""
        now = self.clock()
        removed = 0
        with self.lock:
            for cat in self.categories():
                limit = now - timedelta(days=days.get(cat, default))
                seals = self.seals(cat)
                gone = {x["file"] for x in seals if x.get("type") == "prune"}
                prev = seals[-1]["chain"] if seals else GENESIS
                seq = seals[-1]["seq"] + 1 if seals else 1
                for x in seals:
                    end = slot_end(x["file"])
                    if x.get("type") == "prune" or x["file"] in gone or end is None or end > limit:
                        continue
                    if can_prune is not None and not can_prune(cat, x["file"]):
                        continue  # noch nicht auf dem Langzeitziel bestätigt
                    path = self.root / cat / x["file"]
                    at = now.isoformat(timespec="seconds")
                    chain = _chain(prev, seq, "prune:" + x["file"], x["sha256"], 0, at)
                    rec = {"seq": seq, "category": cat, "type": "prune", "file": x["file"], "sha256": x["sha256"],
                           "bytes": 0, "prev": prev, "sealed_at": at, "chain": chain,
                           "sig": self.key.sign(chain.encode()).hex()}
                    self._append(cat, rec)  # erst vermerken, dann löschen (Absturz dazwischen = Datei fehlt nicht)
                    path.unlink(missing_ok=True)
                    prev, seq, removed = chain, seq + 1, removed + 1
        return {"pruned": removed}

    def restore_events(self, cat: str, since: str, until: str):
        """Prüft die Dateien des Zeitraums und liefert (Datei, Zeilen) – bricht bei Integritätsfehlern ab."""
        res = self.verify(since, until)
        bad = [p for p in res["problems"] if p.get("category") == cat and p["problem"] != "unsealed_old"]
        if bad:
            raise ValueError("integrity:" + bad[0]["problem"])
        import gzip
        out = []
        for x in self.seals(cat):
            day = x["file"][:10].replace("/", "-")
            if x.get("type") == "prune" or day < since or day > until:
                continue
            path = self.root / cat / x["file"]
            if path.is_file():
                with gzip.open(path, "rt", encoding="utf-8") as fh:
                    out.append((x["file"], [ln for ln in fh if ln.strip()]))
        return out

    # ---- Prüfen ----
    def verify(self, since: str | None = None, until: str | None = None, pub: Ed25519PublicKey | None = None,
               ) -> dict[str, Any]:
        """Kette, Signaturen und Dateien prüfen; ``since``/``until`` (YYYY-MM-DD) begrenzen die Dateiprüfung.

        Kette und Signaturen werden immer vollständig geprüft (Lücken im Siegelprotokoll sind sonst nicht sichtbar).
        """
        pub = pub or self.pub
        problems: list[dict[str, Any]] = []
        checked = 0
        unsealed = 0
        cats: dict[str, dict[str, Any]] = {}
        now = self.clock()
        with self.lock:
            names = sorted(set(self.categories()) | {p.stem for p in (self.root / SEALS_DIR).glob("*.jsonl")}
                           if (self.root / SEALS_DIR).is_dir() else self.categories())
            for cat in names:
                try:
                    seals = self.seals(cat)
                except ValueError:
                    problems.append({"category": cat, "problem": "seal_log_corrupt"})
                    continue
                prev, n = GENESIS, 0
                pruned = {x.get("file") for x in seals if x.get("type") == "prune"}
                for i, s in enumerate(seals, 1):
                    where = {"category": cat, "file": s.get("file"), "seq": s.get("seq")}
                    try:
                        if s["seq"] != i or s["prev"] != prev:
                            problems.append({**where, "problem": "chain_broken"})
                        is_prune = s.get("type") == "prune"
                        name = ("prune:" if is_prune else "") + s["file"]
                        if s["chain"] != _chain(s["prev"], s["seq"], name, s["sha256"], s["bytes"],
                                                s["sealed_at"]):
                            problems.append({**where, "problem": "seal_modified"})
                        try:
                            pub.verify(bytes.fromhex(s["sig"]), s["chain"].encode())
                        except (InvalidSignature, ValueError):
                            problems.append({**where, "problem": "signature_invalid"})
                        prev = s["chain"]
                        if is_prune or s["file"] in pruned:
                            continue
                        day = s["file"][:10].replace("/", "-")
                        if (since and day < since) or (until and day > until):
                            continue
                        path = self.root / cat / s["file"]
                        if not path.is_file():
                            problems.append({**where, "problem": "file_missing"})
                            continue
                        sha, size = sha256_file(path)
                        checked += 1
                        n += 1
                        if sha != s["sha256"] or size != s["bytes"]:
                            problems.append({**where, "problem": "file_modified"})
                    except (KeyError, TypeError):
                        problems.append({**where, "problem": "seal_malformed"})
                done = {s.get("file") for s in seals}
                pending = [f for f in self.files(cat) if f not in done]
                for rel in pending:
                    end = slot_end(rel)
                    if end and now >= end + GRACE + timedelta(hours=2):
                        unsealed += 1
                        problems.append({"category": cat, "file": rel, "problem": "unsealed_old"})
                cats[cat] = {"seals": len(seals) - len(pruned), "files": n,
                             "last": seals[-1]["file"] if seals else None,
                             "pending": len(pending)}
        return {"ok": not problems, "checked_files": checked, "unsealed": unsealed, "problems": problems[:200],
                "problem_count": len(problems), "categories": cats, "at": now.isoformat(timespec="seconds")}

    def status(self) -> dict[str, Any]:
        cats: dict[str, Any] = {}
        total = 0
        for cat in self.categories():
            files = self.files(cat)
            size = sum((self.root / cat / f).stat().st_size for f in files)
            seals = self.seals(cat)
            total += size
            cats[cat] = {"files": len(files), "bytes": size, "sealed": sum(1 for x in seals if x.get("type") != "prune"
                                       and (self.root / cat / x["file"]).is_file()),
                         "pruned": sum(1 for x in seals if x.get("type") == "prune"),
                         "last_sealed": seals[-1]["sealed_at"] if seals else None,
                         "oldest": files[0] if files else None, "newest": files[-1] if files else None}
        return {"categories": cats, "bytes": total, "public_key": public_hex(self.key),
                "algorithm": "Ed25519", "timestamp_authority": None}


class Worker(threading.Thread):
    """Versiegelt alle 15 min; tägliche Prüfung im Wartungsfenster. Fehler → Audit-Ereignis (Critical-Alarm)."""

    def __init__(self, archive: Archive, state_path: Path,
                 report: Callable[[str, str, dict[str, Any]], None] | None = None,
                 retention: Any = None, restorer: Any = None, config: Any = None,
                 replicator: Any = None, on_daily: Callable[[], None] | None = None) -> None:
        super().__init__(daemon=True, name="archive")
        self.retention = retention
        self.config = config
        self.replicator = replicator
        self.on_daily = on_daily
        self.restorer = restorer
        self.archive = archive
        self.state_path = state_path
        self.report = report or (lambda *_a: None)
        self.stop = threading.Event()

    def state(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state_path.read_text("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, **kv: Any) -> None:
        data = {**self.state(), **kv}
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), "utf-8")
            os.replace(tmp, self.state_path)
        except OSError:
            pass

    def run_seal(self) -> dict[str, Any]:
        try:
            res = self.archive.seal()
            self._save(seal={"at": self.archive.clock().isoformat(timespec="seconds"), "ok": True, **res})
            return {"ok": True, **res}
        except (OSError, ValueError) as exc:
            self._save(seal={"at": self.archive.clock().isoformat(timespec="seconds"), "ok": False,
                             "error": str(exc)[:200]})
            self.report("archive.seal", "failure", {"error": str(exc)[:200]})
            return {"ok": False, "error": str(exc)[:200]}

    def run_verify(self, since: str | None = None, until: str | None = None) -> dict[str, Any]:
        try:
            res = self.archive.verify(since, until)
        except (OSError, ValueError) as exc:
            res = {"ok": False, "problems": [{"problem": "verify_error", "error": str(exc)[:200]}],
                   "problem_count": 1, "checked_files": 0, "categories": {}, "unsealed": 0,
                   "at": self.archive.clock().isoformat(timespec="seconds")}
        if self.config is not None:
            from . import archive_ext
            extra = archive_ext.verify_stamps(self.archive)
            if extra:
                res["problems"] = (res["problems"] + extra)[:200]
                res["problem_count"] += len(extra)
                res["ok"] = False
        if not since and not until:
            self._save(verify={"at": res["at"], "ok": res["ok"], "checked_files": res["checked_files"],
                               "problem_count": res["problem_count"], "day": res["at"][:10]})
        if not res["ok"]:
            self.report("archive.integrity", "failure", {"problems": res["problem_count"],
                                                         "first": res["problems"][:3]})
        return res

    def run_replicate(self) -> dict[str, Any]:
        if self.replicator is None:
            return {"replicated": 0}
        try:
            res = self.replicator.run()
        except (OSError, ValueError) as exc:
            res = {"replicated": 0, "failed": 1, "error": str(exc)[:120]}
        stamp = self.archive.clock().isoformat(timespec="seconds")
        self._save(replicate={"at": stamp, **res})
        if res.get("failed"):
            self.report("archive.replicate", "failure", {"failed": res["failed"], "error": res.get("error", "")})
        return res

    def run_stamp(self) -> dict[str, Any]:
        if self.config is None:
            return {"stamped": 0}
        from . import archive_ext
        res = archive_ext.stamp_all(self.archive, self.config)
        stamp = self.archive.clock().isoformat(timespec="seconds")
        self._save(stamp={"at": stamp, "day": stamp[:10], **res})
        if res.get("error"):
            self.report("archive.timestamp", "failure", {"error": res["error"]})
        return res

    def run_prune(self) -> dict[str, Any]:
        if self.retention is None:
            return {"pruned": 0}
        cfg = self.retention.get()
        try:
            can = self.replicator.is_replicated if self.replicator and self.replicator.enabled() else None
            res = self.archive.prune(cfg["days"], cfg["default"], can)
        except (OSError, ValueError) as exc:
            self.report("archive.prune", "failure", {"error": str(exc)[:200]})
            return {"pruned": 0, "error": str(exc)[:200]}
        stamp = self.archive.clock().isoformat(timespec="seconds")
        self._save(prune={"at": stamp, "day": stamp[:10], **res})
        if self.on_daily is not None:
            with contextlib.suppress(Exception):  # Fall-Bereinigung darf die Archivpflege nie stoppen
                self.on_daily()
        if res["pruned"]:
            self.report("archive.prune", "success", res)
        return res

    def run(self) -> None:
        next_seal = 0.0
        while not self.stop.wait(30):
            now = self.archive.clock()
            if now.timestamp() >= next_seal:
                next_seal = now.timestamp() + SEAL_INTERVAL
                self.run_seal()
                self.run_replicate()
            local = now.astimezone()
            if 2 <= local.hour < 4 and self.state().get("verify", {}).get("day") != now.isoformat()[:10]:
                self.run_verify()
            if 1 <= local.hour < 2 and self.state().get('stamp', {}).get('day') != now.isoformat()[:10]:
                self.run_stamp()
            if 4 <= local.hour < 5 and self.state().get("prune", {}).get("day") != now.isoformat()[:10]:
                self.run_prune()
            if self.restorer is not None:
                with contextlib.suppress(Exception):  # Ablaufbereinigung darf den Dienst nie beenden
                    self.restorer.expire()
