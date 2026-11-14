"""Benachrichtigung: Verschlüsselung der Zugangsdaten, Mindest-Schweregrad, Teams-Nutzlast, Webhook-Prüfung."""

from __future__ import annotations

import json

import pytest

from siem_api import notify

ALERT = {"rule": {"name": "Regel", "description": "Beschreibung", "mitre": ["T1110"]}, "severity": "high",
         "summary": "Zusammenfassung", "sample": "Beispielzeile", "group": "10.0.0.5", "count": 12}
CFG = {"email_enabled": True, "smtp_host": "mail.example.org", "smtp_port": 587, "smtp_security": "starttls",
       "smtp_user": "u", "mail_from": "siem@example.org", "mail_to": ["a@example.org"], "teams_enabled": True,
       "min_severity": "high"}


def store(tmp_path):
    return notify.Store(tmp_path, b"k" * 32)


def test_secrets_encrypted_and_never_exposed(tmp_path):
    s = store(tmp_path)
    s.save(CFG, "GeheimesKennwort", "https://prod-1.westeurope.logic.azure.com/workflows/abc")
    raw = (tmp_path / "notify.json").read_text("utf-8")
    assert "GeheimesKennwort" not in raw and "logic.azure.com" not in raw
    assert s.secret("smtp_password") == "GeheimesKennwort"
    c = s.config()
    assert c["has_smtp_password"] and c["has_teams_url"] and "GeheimesKennwort" not in json.dumps(c)
    s.save({**CFG, "smtp_port": 25}, None, None)  # Update ohne neues Geheimnis behält das alte
    assert s.secret("smtp_password") == "GeheimesKennwort" and s.config()["smtp_port"] == 25


@pytest.mark.parametrize("url,ok", [("https://prod.logic.azure.com/x", True), ("http://x.example.org/a", False),
                                    ("https://127.0.0.1/x", False), ("https://10.1.1.1/x", False),
                                    ("https://localhost/x", False), ("ftp://a.b/c", False)])
def test_webhook_validation(url, ok):
    assert notify.valid_webhook(url) is ok


def test_invalid_settings_rejected(tmp_path):
    s = store(tmp_path)
    with pytest.raises(notify.NotifyError):
        s.save({**CFG, "mail_to": ["kein-mail"]}, None, None)
    with pytest.raises(notify.NotifyError):
        s.save(CFG, None, "http://unsicher.example.org/x")
    with pytest.raises(notify.NotifyError):
        s.save({**CFG, "smtp_host": "bad host!"}, None, None)


def test_dispatch_min_severity_and_channels(tmp_path):
    s = store(tmp_path)
    s.save(CFG, "pw", "https://prod.logic.azure.com/x")
    sent: list = []

    def em(cfg, pw, subj, body):
        sent.append(("mail", pw, subj, body))

    def tm(url, subj, body, sev):
        sent.append(("teams", url, sev))

    notify.dispatch(s, {**ALERT, "severity": "medium"}, em, tm)
    assert sent == []  # unter Mindest-Schweregrad
    notify.dispatch(s, ALERT, em, tm)
    assert [x[0] for x in sent] == ["mail", "teams"]
    assert "HIGH: Regel" in sent[0][2] and "Beispielzeile" in sent[0][3] and "T1110" in sent[0][3]
    assert s.state()["email"]["ok"] and s.state()["teams"]["ok"]


def test_dispatch_failure_recorded_not_raised(tmp_path):
    s = store(tmp_path)
    s.save({**CFG, "teams_enabled": False}, "pw", None)

    def boom(*_a):
        raise notify.NotifyError("notify_email_failed")

    notify.dispatch(s, ALERT, boom, boom)
    st = s.state()["email"]
    assert st["ok"] is False and st["error"] == "notify_email_failed"


def test_teams_payload_shape():
    p = notify.teams_payload("Betreff", "Text", "critical")
    card = p["attachments"][0]["content"]
    assert p["type"] == "message" and card["type"] == "AdaptiveCard" and card["body"][0]["color"] == "Attention"


def test_api_requires_login(app):
    from fastapi.testclient import TestClient
    c = TestClient(app)
    assert c.get("/api/notifications").status_code in (401, 403)
    assert c.post("/api/notifications/test", json={"channel": "email"}).status_code in (401, 403)
