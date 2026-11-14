"""Fall-Verwaltung (Spec 4.15): Ereignisse, Notizen und Beweise bündeln; Abschluss in ein Write-once-Fallarchiv.

Beim Schließen wird ein signiertes Beweispaket (forensic_export.build) erzeugt, unter ``<archiv>/_cases/<id>/`` abgelegt
und schreibgeschützt (0444); SHA-256 und Ed25519-Signatur stehen in der Datenbank und im Audit-Log. Geschlossene
Fälle sind unveränderlich. Nach der Aufbewahrungsfrist (Standard 12 Monate ab Schließung) werden sie gelöscht; die
Löschung wird im Audit-Log vermerkt.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import forensic_export as fx
from .models import Case, CaseItem

DEFAULT_RETENTION_MONTHS = 12
MAX_ITEMS = 5000


class CaseError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _now() -> datetime:
    return datetime.now(UTC)


def view(c: Case, items: list[CaseItem] | None = None, with_events: bool = True) -> dict[str, Any]:
    out = {"id": c.id, "title": c.title, "description": c.description, "status": c.status,
           "created_by": c.created_by, "created_at": c.created_at.isoformat(), "retention_months": c.retention_months,
           "closed_at": c.closed_at.isoformat() if c.closed_at else None, "closed_by": c.closed_by,
           "package_sha256": c.package_sha256}
    if items is not None:
        out["items"] = [{"id": i.id, "kind": i.kind, "added_by": i.added_by, "added_at": i.added_at.isoformat(),
                         "sha256": i.sha256,
                         "content": json.loads(i.content) if (i.kind == "note" or with_events) else None}
                        for i in items]
    return out


def create(db: Session, title: str, description: str, user: str, retention_months: int) -> Case:
    c = Case(title=title.strip()[:200], description=description[:4000], status="open", created_by=user,
             created_at=_now(), retention_months=retention_months)
    db.add(c)
    db.commit()
    return c


def get(db: Session, cid: int) -> Case:
    c = db.get(Case, cid)
    if c is None:
        raise CaseError("case_not_found")
    return c


def items(db: Session, cid: int) -> list[CaseItem]:
    return list(db.scalars(select(CaseItem).where(CaseItem.case_id == cid).order_by(CaseItem.id)))


def add_item(db: Session, c: Case, kind: str, content: dict[str, Any], user: str) -> CaseItem:
    if c.status != "open":
        raise CaseError("case_closed")
    if len(items(db, c.id)) >= MAX_ITEMS:
        raise CaseError("case_full")
    raw = json.dumps(content, sort_keys=True, ensure_ascii=False)
    it = CaseItem(case_id=c.id, kind=kind, content=raw, sha256=hashlib.sha256(raw.encode()).hexdigest(),
                  added_by=user, added_at=_now())
    db.add(it)
    db.commit()
    return it


def case_dir(root: Path, cid: int) -> Path:
    return root / "_cases" / str(cid)


def close(db: Session, c: Case, user: str, root: Path, key: Ed25519PrivateKey, audit_key: bytes) -> dict[str, Any]:
    if c.status != "open":
        raise CaseError("case_closed")
    its = items(db, c.id)
    events = [json.loads(i.content) for i in its if i.kind == "event"]
    notes = [{"by": i.added_by, "at": i.added_at.isoformat(), **json.loads(i.content)} for i in its if i.kind == "note"]
    meta = {"case": c.id, "title": c.title, "description": c.description, "created_by": c.created_by,
            "created_at": c.created_at.isoformat(), "closed_by": user, "notes": notes,
            "item_hashes": [i.sha256 for i in its]}
    data, digest = fx.build(events, meta, audit_key)
    d = case_dir(root, c.id)
    d.mkdir(mode=0o750, parents=True, exist_ok=True)
    pkg = d / "package.zip"
    if pkg.exists():
        raise CaseError("case_archive_exists")  # Write-once: nie überschreiben
    tmp = d / "package.zip.part"
    tmp.write_bytes(data)
    os.chmod(tmp, 0o444)
    os.replace(tmp, pkg)
    c.status, c.closed_at, c.closed_by = "closed", _now(), user
    c.package_sha256 = digest
    c.package_sig = key.sign(bytes.fromhex(digest)).hex()
    db.commit()
    return {"sha256": digest, "signature": c.package_sig}


def package(c: Case, root: Path) -> bytes:
    if c.status != "closed":
        raise CaseError("case_not_closed")
    p = case_dir(root, c.id) / "package.zip"
    try:
        data = p.read_bytes()
    except OSError:
        raise CaseError("case_package_missing") from None
    if hashlib.sha256(data).hexdigest() != c.package_sha256:
        raise CaseError("case_package_modified")
    return data


def purge_expired(db: Session, root: Path, now: datetime | None = None) -> list[int]:
    """Geschlossene Fälle nach Ablauf der Aufbewahrung löschen; Rückgabe der gelöschten Fall-IDs."""
    now = now or _now()
    gone: list[int] = []
    for c in db.scalars(select(Case).where(Case.status == "closed")):
        closed = c.closed_at.replace(tzinfo=UTC) if c.closed_at.tzinfo is None else c.closed_at
        months = closed.year * 12 + closed.month - 1 + c.retention_months
        due = closed.replace(year=months // 12, month=months % 12 + 1, day=min(closed.day, 28))
        if now >= due:
            d = case_dir(root, c.id)
            for f in d.glob("*"):
                f.chmod(0o644)
                f.unlink(missing_ok=True)
            d.rmdir() if d.exists() else None
            db.delete(c)
            gone.append(c.id)
    if gone:
        db.commit()
    return gone
