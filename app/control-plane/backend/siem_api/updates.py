"""Update-Prüfung (Spec 4.14, ADR-21): neue Versionen aus GitHub Releases erkennen.

Die Prüfung ist rein lesend (ETag-fähig, Token optional und verschlüsselt). Das Einspielen erfolgt weiterhin über
das signierte Paket mit ``install.sh --upgrade`` bzw. den Bootstrap-Weg; der automatische Abruf mit Signaturprüfung
ist für eine spätere Version vorgesehen.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__, sophos
from .security import crypto

CONTEXT = "updates.token"
DEFAULT_REPO = "giti4ge/kmu-siem-releases"
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_VER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?")


class UpdateError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse(v: str) -> tuple[int, int, int, int, str] | None:
    """Version → vergleichbares Tupel; Vorabversionen (``-beta.1``, ``-dev``) sind kleiner als die Release-Version."""
    m = _VER.match(v.strip())
    if not m:
        return None
    pre = m.group(4) or ""
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, pre


class Store:
    def __init__(self, secrets_dir: Path, master_key: bytes) -> None:
        self.path = secrets_dir / "updates.json"
        self.key = master_key

    def config(self) -> dict[str, Any]:
        c = sophos._read(self.path)
        return {"repo": c.get("repo", DEFAULT_REPO), "channel": c.get("channel", "stable"), "has_token": bool(c.get("token")),
                "last_check": c.get("last_check"), "latest": c.get("latest")}

    def token(self) -> str:
        blob = sophos._read(self.path).get("token")
        if not blob:
            return ""
        try:
            return crypto.decrypt(self.key, base64.b64decode(blob), CONTEXT)
        except (crypto.DecryptionError, ValueError) as exc:
            raise UpdateError("update_secret_unreadable") from exc

    def save(self, repo: str, channel: str, token: str | None) -> None:
        if not _REPO.match(repo) or channel not in ("stable", "beta"):
            raise UpdateError("update_invalid_settings")
        old = sophos._read(self.path)
        data = {**old, "repo": repo, "channel": channel}
        if token:
            data["token"] = base64.b64encode(crypto.encrypt(self.key, token, CONTEXT)).decode()
        sophos._write(self.path, data)

    def remember(self, latest: dict[str, Any] | None) -> None:
        sophos._write(self.path, {**sophos._read(self.path), "latest": latest,
                                  "last_check": datetime.now(UTC).isoformat(timespec="seconds")})


def _fetch(url: str, token: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "kmu-siem",  # noqa: S310
                                               **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 – feste https-URL
            return json.loads(r.read(4_000_000))
    except urllib.error.HTTPError as exc:
        raise UpdateError("update_not_found" if exc.code == 404 else "update_auth_failed" if exc.code in (401, 403)
                          else "update_failed") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise UpdateError("update_unreachable") from exc


def newest(releases: list[dict[str, Any]], channel: str, current: str = __version__) -> dict[str, Any] | None:
    """Neueste passende Version (Kanal stable: keine Vorabversionen) oder None, wenn nichts Neueres existiert."""
    cur = parse(current)
    best: tuple[Any, dict[str, Any]] | None = None
    for r in releases:
        if r.get("draft") or (channel == "stable" and r.get("prerelease")):
            continue
        v = parse(str(r.get("tag_name", "")))
        if v and v[3] == 1 or (v and channel == "beta"):
            if best is None or v > best[0]:  # type: ignore[operator]
                best = (v, r)
    if not best or (cur and best[0] <= cur):
        return None
    r = best[1]
    return {"version": str(r["tag_name"]).lstrip("v"), "name": r.get("name") or r["tag_name"], "notes": str(r.get("body") or "")[:4000],
            "published": r.get("published_at"), "prerelease": bool(r.get("prerelease")), "url": r.get("html_url")}


def check(store: Store, fetch: Callable[[str, str], Any] = _fetch) -> dict[str, Any]:
    cfg = store.config()
    releases = fetch(f"https://api.github.com/repos/{cfg['repo']}/releases?per_page=30", store.token())
    latest = newest(releases if isinstance(releases, list) else [], cfg["channel"])
    store.remember(latest)
    return {"current": __version__, "latest": latest}
