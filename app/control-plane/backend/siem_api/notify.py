"""Benachrichtigung (Spec 4.7): E-Mail (SMTP) und Microsoft Teams (Workflows-Webhook).

Zugangsdaten (SMTP-Kennwort, Webhook-URL) liegen verschlüsselt in ``notify.json``. Versandfehler werden gezählt und
im Zustand (``notify-state.json``) angezeigt; sie stoppen die Alert-Engine nie.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import re
import smtplib
import ssl
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import sophos
from .security import crypto

log = logging.getLogger("siem.notify")
CONTEXT = "notify.secret"
SEVERITIES = ("low", "medium", "high", "critical")
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
_MAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,200}\.[A-Za-z]{2,}$")
_COLOR = {"low": "Default", "medium": "Warning", "high": "Attention", "critical": "Attention"}


class NotifyError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def valid_webhook(url: str) -> bool:
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname:
        return False
    try:
        ip = ipaddress.ip_address(p.hostname)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return bool(_HOST.match(p.hostname)) and p.hostname != "localhost"


class Store:
    def __init__(self, secrets_dir: Path, master_key: bytes) -> None:
        self.path = secrets_dir / "notify.json"
        self.state_path = secrets_dir / "notify-state.json"
        self.key = master_key

    def config(self) -> dict[str, Any]:
        c = sophos._read(self.path)
        return {"email_enabled": bool(c.get("email_enabled")), "smtp_host": c.get("smtp_host", ""),
                "smtp_port": int(c.get("smtp_port", 587)), "smtp_security": c.get("smtp_security", "starttls"),
                "smtp_user": c.get("smtp_user", ""), "has_smtp_password": bool(c.get("smtp_password")),
                "mail_from": c.get("mail_from", ""), "mail_to": list(c.get("mail_to", [])),
                "teams_enabled": bool(c.get("teams_enabled")), "has_teams_url": bool(c.get("teams_url")),
                "min_severity": c.get("min_severity", "high")}

    def secret(self, name: str) -> str:
        blob = sophos._read(self.path).get(name)
        if not blob:
            return ""
        try:
            return crypto.decrypt(self.key, base64.b64decode(blob), CONTEXT)
        except (crypto.DecryptionError, ValueError) as exc:
            raise NotifyError("notify_secret_unreadable") from exc

    def save(self, c: dict[str, Any], smtp_password: str | None, teams_url: str | None) -> None:
        host = c["smtp_host"].strip()
        if host and not _HOST.match(host):
            raise NotifyError("notify_invalid_host")
        if c["smtp_security"] not in ("starttls", "ssl", "none") or not 1 <= c["smtp_port"] <= 65535:
            raise NotifyError("notify_invalid_settings")
        if c["min_severity"] not in SEVERITIES:
            raise NotifyError("notify_invalid_settings")
        to = [a.strip() for a in c["mail_to"] if a.strip()]
        if any(not _MAIL.match(a) for a in to + ([c["mail_from"]] if c["mail_from"] else [])) or len(to) > 20:
            raise NotifyError("notify_invalid_address")
        if teams_url and not valid_webhook(teams_url):
            raise NotifyError("notify_invalid_webhook")
        old = sophos._read(self.path)
        keys = ("email_enabled", "smtp_port", "smtp_security", "smtp_user", "mail_from", "teams_enabled",
                "min_severity")
        data = {**{k: c[k] for k in keys}, "smtp_host": host, "mail_to": to,
                "smtp_password": old.get("smtp_password"), "teams_url": old.get("teams_url")}
        if smtp_password:
            data["smtp_password"] = base64.b64encode(crypto.encrypt(self.key, smtp_password, CONTEXT)).decode()
        if teams_url:
            data["teams_url"] = base64.b64encode(crypto.encrypt(self.key, teams_url, CONTEXT)).decode()
        sophos._write(self.path, data)

    def state(self) -> dict[str, Any]:
        return sophos._read(self.state_path)

    def record(self, channel: str, ok: bool, error: str = "") -> None:
        st = self.state()
        st[channel] = {"at": datetime.now(UTC).isoformat(timespec="seconds"), "ok": ok, "error": error[:200]}
        try:
            sophos._write(self.state_path, st)
        except OSError:
            pass


def render(alert: dict[str, Any]) -> tuple[str, str]:
    """(Betreff, Text) einer Alarmmeldung; enthält die Beschreibung, aber keine Zugangsdaten."""
    rule = alert["rule"]
    subject = f"[KMU-SIEM] {alert['severity'].upper()}: {rule['name']}"
    lines = [alert["summary"], "", rule.get("description", ""), "", f"Schweregrad: {alert['severity']}",
             f"MITRE ATT&CK: {', '.join(rule.get('mitre', [])) or '-'}"]
    if alert.get("sample"):
        lines += ["", "Beispiel:", str(alert["sample"])]
    lines += ["", "Details im Web-UI unter „Alarme“."]
    return subject, "\n".join(lines)


def send_email(cfg: dict[str, Any], password: str, subject: str, body: str, timeout: float = 20.0) -> None:
    if not (cfg["smtp_host"] and cfg["mail_from"] and cfg["mail_to"]):
        raise NotifyError("notify_email_not_configured")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = cfg["mail_from"], ", ".join(cfg["mail_to"]), subject[:200]
    msg.set_content(body)
    ctx = ssl.create_default_context()
    try:
        if cfg["smtp_security"] == "ssl":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], timeout=timeout, context=ctx)
        else:
            smtp = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=timeout)
        with smtp:
            if cfg["smtp_security"] == "starttls":
                smtp.starttls(context=ctx)
            if cfg["smtp_user"] and password:
                smtp.login(cfg["smtp_user"], password)
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise NotifyError("notify_email_failed") from exc


def teams_payload(subject: str, body: str, severity: str) -> dict[str, Any]:
    return {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
        "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                    "version": "1.4", "body": [
                        {"type": "TextBlock", "text": subject, "weight": "Bolder", "size": "Medium",
                         "color": _COLOR.get(severity, "Default"), "wrap": True},
                        {"type": "TextBlock", "text": body, "wrap": True}]}}]}


def send_teams(url: str, subject: str, body: str, severity: str, timeout: float = 20.0) -> None:
    if not url or not valid_webhook(url):
        raise NotifyError("notify_teams_not_configured")
    req = urllib.request.Request(url, data=json.dumps(teams_payload(subject, body, severity)).encode(),  # noqa: S310
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 – nur https (valid_webhook)
            resp.read(2000)
    except (urllib.error.URLError, OSError) as exc:
        raise NotifyError("notify_teams_failed") from exc


def dispatch(store: Store, alert: dict[str, Any], email=send_email, teams=send_teams) -> None:
    """Alarm an die aktivierten Kanäle senden (ab der eingestellten Mindest-Schweregrad)."""
    cfg = store.config()
    if SEVERITIES.index(alert["severity"]) < SEVERITIES.index(cfg["min_severity"]):
        return
    subject, body = render(alert)
    if cfg["email_enabled"]:
        try:
            email(cfg, store.secret("smtp_password"), subject, body)
            store.record("email", True)
        except NotifyError as exc:
            store.record("email", False, exc.code)
            log.warning("E-Mail-Versand fehlgeschlagen: %s", exc.code)
    if cfg["teams_enabled"]:
        try:
            teams(store.secret("teams_url"), subject, body, alert["severity"])
            store.record("teams", True)
        except NotifyError as exc:
            store.record("teams", False, exc.code)
            log.warning("Teams-Versand fehlgeschlagen: %s", exc.code)
