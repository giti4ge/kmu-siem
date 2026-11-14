"""Sophos Central: XDR Data Lake (primär) mit automatischem Fallback auf die SIEM Integration API (Spec 4.8).

Ablauf je Zyklus (alle 10 min, Zeitfenster mit Überlappung, Deduplizierung über Ereignis-ID):
  Token (OAuth2 Client Credentials) → Whoami (Mandant, Region) → Modus bestimmen → Ereignisse abrufen →
  nach ECS normalisieren → als JSON-Zeilen an Vector (127.0.0.1:10601) → Zustand speichern.
Formate und Tabellen nicht an echten Mandanten verifiziert (SPEC R-04/R-14); unbekannte Felder bleiben unter `sophos.*`.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .security import crypto

TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token"  # noqa: S105 – öffentlicher Endpunkt
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"
VECTOR_ADDR = ("127.0.0.1", 10601)
INTERVAL_SECONDS = 600
OVERLAP = timedelta(minutes=15)
MODES = ("auto", "datalake", "siem")
SEEN_MAX = 20000
CONTEXT = "sophos.client_secret"

# Query-Set Data Lake (SQL-Dialekt der Sophos XDR Data Lake); Tabellen je Lizenz/Region prüfen (R-14)
DATALAKE_QUERIES: dict[str, str] = {
    "detections": "SELECT * FROM xdr_ioc_detections WHERE detection_time >= '{from_}' AND detection_time < '{to}'",
    "logons": ("SELECT * FROM xdr_data WHERE query_name = 'user_logons' AND "
               "ingest_time >= '{from_}' AND ingest_time < '{to}'"),
}


class SophosError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NoLicense(SophosError):
    """Data Lake nicht verfügbar (keine Lizenz/Berechtigung) → Fallback."""


# ---------------------------------------------------------------- Konfiguration und Zustand

def _read(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


class Store:
    """Konfiguration (Secret verschlüsselt) und Laufzustand im Secrets-Verzeichnis."""

    def __init__(self, secrets_dir: Path, master_key: bytes) -> None:
        self.cfg_path = secrets_dir / "sophos.json"
        self.state_path = secrets_dir / "sophos-state.json"
        self.key = master_key
        self.lock = threading.Lock()

    def config(self) -> dict[str, Any]:
        c = _read(self.cfg_path)
        return {"enabled": bool(c.get("enabled")), "client_id": c.get("client_id", ""),
                "mode": c.get("mode", "auto") if c.get("mode") in MODES else "auto",
                "has_secret": bool(c.get("secret"))}

    def secret(self) -> str:
        blob = _read(self.cfg_path).get("secret")
        if not blob:
            raise SophosError("sophos_not_configured")
        try:
            return crypto.decrypt(self.key, base64.b64decode(blob), CONTEXT)
        except (crypto.DecryptionError, ValueError) as exc:
            raise SophosError("sophos_secret_unreadable") from exc

    def save(self, *, enabled: bool, client_id: str, mode: str, client_secret: str | None) -> None:
        old = _read(self.cfg_path)
        data = {"enabled": enabled, "client_id": client_id.strip(), "mode": mode, "secret": old.get("secret")}
        if client_secret:
            data["secret"] = base64.b64encode(crypto.encrypt(self.key, client_secret, CONTEXT)).decode()
        _write(self.cfg_path, data)

    def state(self) -> dict[str, Any]:
        return _read(self.state_path)

    def save_state(self, st: dict[str, Any]) -> None:
        _write(self.state_path, st)


# ---------------------------------------------------------------- HTTP-Client

def _http(method: str, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None,
          timeout: float = 30.0) -> Any:
    if not url.startswith("https://"):
        raise SophosError("sophos_bad_url")
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})  # noqa: S310 – https erzwungen
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise NoLicense("sophos_forbidden") from exc
        if exc.code == 429:
            raise SophosError("sophos_rate_limited") from exc
        raise SophosError(f"sophos_http_{exc.code}") from exc
    except (OSError, ValueError) as exc:
        raise SophosError("sophos_unreachable") from exc


class Central:
    def __init__(self, client_id: str, client_secret: str, http=_http) -> None:
        self.client_id, self.client_secret, self.http = client_id, client_secret, http
        self.token = ""
        self.tenant = ""
        self.api = ""

    def connect(self) -> None:
        form = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                                       "client_secret": self.client_secret, "scope": "token"}).encode()
        try:
            tok = self.http("POST", TOKEN_URL, body=form,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
        except NoLicense as exc:
            raise SophosError("sophos_auth_failed") from exc
        self.token = str(tok.get("access_token", ""))
        if not self.token:
            raise SophosError("sophos_auth_failed")
        who = self.http("GET", WHOAMI_URL, headers=self._h())
        if who.get("idType") != "tenant":
            raise SophosError("sophos_not_tenant")
        self.tenant = str(who["id"])
        self.api = str(who.get("apiHosts", {}).get("dataRegion", ""))
        if not self.api.startswith("https://"):
            raise SophosError("sophos_bad_url")

    def _h(self) -> dict[str, str]:
        h = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if self.tenant:
            h["X-Tenant-ID"] = self.tenant
        return h

    # SIEM Integration API (Fallback)
    def siem(self, kind: str, since: int) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor = ""
        for _ in range(50):
            q = {"limit": "1000"}
            q.update({"cursor": cursor} if cursor else {"from_date": str(since)})
            page = self.http("GET", f"{self.api}/siem/v1/{kind}?{urllib.parse.urlencode(q)}", headers=self._h())
            for it in page.get("items", []):
                it["_kind"] = kind
                items.append(it)
            if not page.get("has_more"):
                break
            cursor = str(page.get("next_cursor", ""))
        return items

    # XDR Data Lake (primär): asynchroner Query-Lauf mit Polling
    def datalake(self, name: str, frm: datetime, to: datetime, sleep=time.sleep) -> list[dict[str, Any]]:
        sql = DATALAKE_QUERIES[name].format(from_=frm.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                                            to=to.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
        body = json.dumps({"adHocQuery": {"template": sql}}).encode()
        h = dict(self._h(), **{"Content-Type": "application/json"})
        run = self.http("POST", f"{self.api}/xdr-query/v1/queries/runs", headers=h, body=body)
        rid = str(run.get("id", ""))
        if not rid:
            raise SophosError("sophos_query_failed")
        for delay in (1, 2, 4, 8, 15, 30, 30, 30, 30, 30):
            st = self.http("GET", f"{self.api}/xdr-query/v1/queries/runs/{rid}", headers=self._h())
            if st.get("status") == "finished":
                if st.get("result") not in (None, "succeeded"):
                    raise SophosError("sophos_query_failed")
                break
            sleep(delay)
        else:
            raise SophosError("sophos_query_timeout")
        rows: list[dict[str, Any]] = []
        url = f"{self.api}/xdr-query/v1/queries/runs/{rid}/results?pageSize=1000"
        for _ in range(100):
            page = self.http("GET", url, headers=self._h())
            for it in page.get("items", []):
                it["_kind"] = f"datalake.{name}"
                rows.append(it)
            nxt = page.get("pages", {}).get("next")
            if not nxt:
                break
            url = f"{self.api}/xdr-query/v1/queries/runs/{rid}/results?pageSize=1000&pageFromKey={urllib.parse.quote(str(nxt))}"
        return rows


# ---------------------------------------------------------------- Normalisierung nach ECS

_SEVERITY = {"none": 0, "low": 3, "medium": 5, "high": 8, "critical": 10, "info": 1}


def _iso(value: Any) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, UTC).isoformat().replace("+00:00", "Z")
    s = str(value or "")
    return s if s else datetime.now(UTC).isoformat().replace("+00:00", "Z")


def event_id(item: dict[str, Any]) -> str:
    return str(item.get("id") or item.get("detection_id") or item.get("event_id")
               or hash(json.dumps(item, sort_keys=True, default=str)))


def normalize(item: dict[str, Any]) -> dict[str, Any]:
    kind = str(item.get("_kind", ""))
    typ = str(item.get("type", ""))
    sev_raw = str(item.get("severity", "")).lower()
    malware = "threat" in typ.lower() or "malware" in typ.lower() or "pua" in typ.lower() or item.get("threat")
    category = "av" if malware and not kind.startswith("datalake") else "edr"
    ts = item.get("created_at") or item.get("when") or item.get("detection_time") or item.get("ingest_time") or item.get("rt")
    host = item.get("location") or item.get("source") or item.get("hostname") or item.get("host_name")
    out: dict[str, Any] = {
        "@timestamp": _iso(ts),
        "siem": {"collector": "sophos", "pipeline": "sophos", "category": category},
        "event": {"kind": "alert" if kind in ("alerts", "datalake.detections") else "event", "module": "sophos",
                  "dataset": f"sophos.{kind}", "id": event_id(item), "action": typ or None,
                  "category": ["malware"] if category == "av" else ["intrusion_detection"],
                  "type": ["info"], "original": json.dumps(item, sort_keys=True, default=str)[:8000],
                  "severity": _SEVERITY.get(sev_raw, 0) if sev_raw else None},
        "observer": {"vendor": "Sophos", "product": "Central", "type": "edr"},
        "message": str(item.get("name") or item.get("description") or typ or kind),
        "host": {"name": host} if host else {},
        "user": {"name": item.get("user") or item.get("username")} if (item.get("user") or item.get("username")) else {},
        "source": {"ip": item.get("source_info", {}).get("ip")} if isinstance(item.get("source_info"), dict)
        and item["source_info"].get("ip") else {},
        "sophos": {k: v for k, v in item.items() if k not in ("_kind",) and not isinstance(v, (dict, list))},
    }
    if item.get("threat"):
        out["threat"] = {"indicator": {"name": str(item["threat"])}}
    return {k: v for k, v in out.items() if v not in (None, {}, [])}


# ---------------------------------------------------------------- Zyklus

def send_to_vector(events: list[dict[str, Any]], addr: tuple[str, int] = VECTOR_ADDR) -> None:
    if not events:
        return
    payload = "".join(json.dumps(e, default=str) + "\n" for e in events).encode()
    try:
        with socket.create_connection(addr, timeout=10) as s:
            s.sendall(payload)
    except OSError as exc:
        raise SophosError("sophos_vector_unavailable") from exc


def run_cycle(store: Store, central_factory=Central, send=send_to_vector, now: datetime | None = None) -> dict[str, Any]:
    """Ein Abrufzyklus. Fehler werden im Zustand vermerkt, nicht geworfen."""
    now = now or datetime.now(UTC)
    cfg = store.config()
    st = store.state()
    result: dict[str, Any] = {"at": now.isoformat(), "error": None, "sent": 0, "mode": None}
    try:
        if not cfg["client_id"] or not cfg["has_secret"]:
            raise SophosError("sophos_not_configured")
        c = central_factory(cfg["client_id"], store.secret())
        c.connect()
        since = datetime.fromisoformat(st["last_to"]) - OVERLAP if st.get("last_to") else now - timedelta(hours=1)
        seen = list(st.get("seen", []))
        mode = cfg["mode"]
        items: list[dict[str, Any]] = []
        if mode in ("auto", "datalake"):
            try:
                for name in DATALAKE_QUERIES:
                    items += c.datalake(name, since, now)
                result["mode"] = "datalake"
            except NoLicense:
                if mode == "datalake":
                    raise
                items = []
                mode = "siem"
        if mode == "siem":
            for kind in ("events", "alerts"):
                items += c.siem(kind, int(since.timestamp()))
            result["mode"] = "siem"
        seen_set = set(seen)
        fresh = [i for i in items if event_id(i) not in seen_set]
        send([normalize(i) for i in fresh])
        seen = (seen + [event_id(i) for i in fresh])[-SEEN_MAX:]
        result["sent"] = len(fresh)
        store.save_state({**st, "last_to": now.isoformat(), "seen": seen, "last_mode": result["mode"]})
    except SophosError as exc:
        result["error"] = exc.code
    store.save_state({**store.state(), "last_run": result})
    return result


class Poller(threading.Thread):
    """Hintergrund-Thread der API: ruft alle 10 min ab, solange die Anbindung aktiviert ist."""

    def __init__(self, store: Store) -> None:
        super().__init__(daemon=True, name="sophos-poller")
        self.store = store
        self.stop = threading.Event()
        self.trigger = threading.Event()

    def run(self) -> None:
        while not self.stop.is_set():
            if self.store.config()["enabled"]:
                with self.store.lock:
                    run_cycle(self.store)
            self.trigger.wait(INTERVAL_SECONDS)
            self.trigger.clear()
