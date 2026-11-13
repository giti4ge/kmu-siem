"""Audit-Log: Hash-Kette und Erkennung von Manipulationen (Abnahmekriterium Phase 2)."""

from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import text

from siem_api.audit import GENESIS
from siem_api.models import AuditEntry


@pytest.fixture
def filled(h):
    with h.db() as db:
        for i in range(10):
            h.st.audit.append(db, actor="adm", action="test.event", target=f"t{i}", details={"i": i})
    return h


def verify(h):
    with h.db() as db:
        return h.st.audit.verify(db)


def test_intact_chain(filled):
    r = verify(filled)
    assert r.ok and r.entries == 10


def test_modified_entry_detected(filled):
    with filled.db() as db:
        db.execute(text("UPDATE audit_log SET target='gefälscht' WHERE seq=4"))
        db.commit()
    r = verify(filled)
    assert not r.ok and r.first_bad_seq == 4 and r.reason == "entry_modified"


def test_modified_details_detected(filled):
    with filled.db() as db:
        db.execute(text("UPDATE audit_log SET details=:d WHERE seq=7"), {"d": '{"i":99}'})
        db.commit()
    assert verify(filled).first_bad_seq == 7


def test_deleted_entry_detected(filled):
    with filled.db() as db:
        db.execute(text("DELETE FROM audit_log WHERE seq=5"))
        db.commit()
    r = verify(filled)
    assert not r.ok and r.first_bad_seq == 6 and r.reason == "sequence_gap"


def test_deleted_and_renumbered_detected(filled):
    # Eintrag löschen und Nachfolger umnummerieren: Kette passt nicht mehr
    with filled.db() as db:
        db.execute(text("DELETE FROM audit_log WHERE seq=5"))
        for seq in range(6, 11):
            db.execute(text("UPDATE audit_log SET seq=:n WHERE seq=:o"), {"n": seq - 1, "o": seq})
        db.commit()
    r = verify(filled)
    assert not r.ok and r.first_bad_seq == 5


def test_truncated_tail_detected(filled):
    with filled.db() as db:
        db.execute(text("DELETE FROM audit_log WHERE seq>=9"))
        db.commit()
    r = verify(filled)
    assert not r.ok and r.reason == "truncated"


def test_rehashed_chain_without_key_detected(filled):
    """Angreifer mit DB-Zugriff berechnet die Kette mit SHA-256 neu – ohne HMAC-Schlüssel erkannt."""
    with filled.db() as db:
        prev = GENESIS
        for e in db.query(AuditEntry).order_by(AuditEntry.seq):
            if e.seq == 3:
                e.target = "gefälscht"
            e.prev_hash = prev
            e.hash = hashlib.sha256(f"{prev}{e.seq}{e.target}".encode()).hexdigest()
            prev = e.hash
        db.commit()
    assert not verify(filled).ok


def test_audit_written_for_logins_and_admin_actions(h):
    h.create_user("adm", ["system-admin"])
    adm = h.login("adm")
    adm.post("/api/users", json={"username": "neu", "password": "Ein-sehr-gutes-Kennwort-42", "roles": ["auditor"]})
    actions = [e["action"] for e in adm.get("/api/audit").json()]
    assert {"auth.login", "auth.totp", "user.create"} <= set(actions)
    entry = next(e for e in adm.get("/api/audit").json() if e["action"] == "user.create")
    assert entry["actor"] == "adm" and entry["target"] == "neu"
    assert json.loads(entry["details"]) == {"roles": ["auditor"]}
    assert "Ein-sehr-gutes" not in json.dumps(adm.get("/api/audit").json())  # nie Kennwörter


def test_verify_endpoint_reports_manipulation(h):
    h.create_user("aud", ["auditor"])
    aud = h.login("aud")
    assert aud.get("/api/audit/verify").json()["ok"] is True
    with h.db() as db:
        db.execute(text("UPDATE audit_log SET actor='jemand' WHERE seq=1"))
        db.commit()
    r = aud.get("/api/audit/verify").json()
    assert r["ok"] is False and r["first_bad_seq"] == 1
