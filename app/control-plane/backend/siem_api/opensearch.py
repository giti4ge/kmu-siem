"""Minimaler OpenSearch-Client der Control-Plane (nur Standardbibliothek, Basic-Auth, interne CA)."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class OpenSearchUnavailable(Exception):
    """OpenSearch nicht erreichbar oder Zugangsdaten fehlen."""


class OpenSearchClient:
    def __init__(self, url: str, secrets_dir: Path, timeout: float = 15.0) -> None:
        self.url = url.rstrip("/")
        self.secrets_dir = secrets_dir
        self.timeout = timeout

    def _credentials(self) -> tuple[str, str]:
        try:
            data = json.loads((self.secrets_dir / "opensearch.json").read_text("utf-8"))
            return str(data["user"]), str(data["password"])
        except (OSError, ValueError, KeyError) as exc:
            raise OpenSearchUnavailable("Zugangsdaten fehlen") from exc

    def request(self, method: str, path: str, body: Any = None) -> Any:
        user, password = self._credentials()
        ca = self.secrets_dir / "opensearch-ca.crt"
        try:
            ctx = ssl.create_default_context(cafile=str(ca))
        except (OSError, ssl.SSLError) as exc:
            raise OpenSearchUnavailable("CA-Zertifikat fehlt") from exc
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)  # noqa: S310 – feste https-URL
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=self.timeout) as resp:  # noqa: S310
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise OpenSearchUnavailable(f"HTTP {exc.code}") from exc
        except (OSError, ValueError) as exc:
            raise OpenSearchUnavailable(str(exc)) from exc

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        return self.request("POST", f"/{index}/_search?ignore_unavailable=true&allow_no_indices=true", body) or {}
