"""Audit-Log mit HMAC-SHA256-Hash-Kette (Spec 5.1).

Jeder Eintrag enthält den Hash seines Vorgängers; der eigene Hash ist ein HMAC über
Vorgänger-Hash und alle Inhaltsfelder. Der HMAC-Schlüssel liegt außerhalb der Datenbank
(data/secrets). Damit wird erkannt:
  - Änderung eines Eintrags (Hash passt nicht mehr),
  - Löschen/Einfügen/Vertauschen in der Mitte (Kette bzw. Sequenznummer bricht),
  - Abschneiden am Ende (Kopf-Datei audit.head mit letzter Sequenz und Hash),
  - Neuberechnen der Kette durch jemanden mit DB-Zugriff, aber ohne Schlüssel.
Zusätzlich werden die Einträge ab Phase 2.2 in den read-only Index siem-audit-* gespiegelt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEntry

GENESIS = "0" * 64


def _canonical(details: dict | None) -> str:
    return json.dumps(details or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(key: bytes, prev_hash: str, e: AuditEntry) -> str:
    payload = "\x1f".join([
        prev_hash, str(e.seq), e.ts, e.actor, e.action, e.target, e.outcome, e.ip, e.details,
    ])
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


class AuditLog:
    def __init__(self, key: bytes, head_file: Path):
        self.key = key
        self.head_file = head_file
        # Sequenznummern lückenlos auch bei parallelen Anfragen (ein Prozess, mehrere Threads)
        self.lock = threading.RLock()

    # --- Kopf (letzte Sequenz + Hash) außerhalb der DB --------------------------------
    def _read_head(self) -> tuple[int, str] | None:
        try:
            seq, h = self.head_file.read_text().split()
            return int(seq), h
        except FileNotFoundError:
            return None
        except ValueError:
            return (-1, "")

    def _write_head(self, seq: int, h: str) -> None:
        tmp = self.head_file.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(f"{seq} {h}\n")
        os.replace(tmp, self.head_file)

    # --- Schreiben -----------------------------------------------------------------
    def append(self, db: Session, *, actor: str, action: str, target: str = "", outcome: str = "success",
               ip: str = "", details: dict | None = None, commit: bool = True) -> AuditEntry:
        with self.lock:
            return self._append(db, actor=actor, action=action, target=target, outcome=outcome, ip=ip,
                                details=details, commit=commit)

    def _append(self, db: Session, *, actor: str, action: str, target: str, outcome: str, ip: str,
                details: dict | None, commit: bool) -> AuditEntry:
        last = db.scalars(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)).first()
        prev_hash = last.hash if last else GENESIS
        entry = AuditEntry(
            seq=(last.seq + 1) if last else 1,
            ts=datetime.now(UTC).isoformat(timespec="microseconds"),
            actor=actor[:64], action=action[:64], target=target[:255], outcome=outcome[:16],
            ip=ip[:64], details=_canonical(details), prev_hash=prev_hash,
        )
        entry.hash = _digest(self.key, prev_hash, entry)
        db.add(entry)
        if commit:
            db.commit()
            self._write_head(entry.seq, entry.hash)
        return entry

    def sync_head(self, db: Session) -> None:
        """Kopf nach einem Commit mit commit=False nachziehen."""
        last = db.scalars(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)).first()
        if last:
            self._write_head(last.seq, last.hash)

    # --- Prüfen ---------------------------------------------------------------------
    def verify(self, db: Session) -> VerifyResult:
        prev_hash = GENESIS
        expected_seq = 1
        count = 0
        for e in db.scalars(select(AuditEntry).order_by(AuditEntry.seq)):
            if e.seq != expected_seq:
                return VerifyResult(False, count, e.seq, "sequence_gap")
            if e.prev_hash != prev_hash:
                return VerifyResult(False, count, e.seq, "chain_broken")
            if not hmac.compare_digest(_digest(self.key, prev_hash, e), e.hash):
                return VerifyResult(False, count, e.seq, "entry_modified")
            prev_hash = e.hash
            expected_seq += 1
            count += 1
        head = self._read_head()
        if head is not None:
            seq, h = head
            if seq != count or (count and h != prev_hash):
                return VerifyResult(False, count, seq, "truncated")
        elif count:
            return VerifyResult(False, count, None, "head_missing")
        return VerifyResult(True, count, None, None)


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    first_bad_seq: int | None
    reason: str | None
