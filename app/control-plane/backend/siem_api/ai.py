"""KI-Bridge (Spec 4.12, ADR-24): Alarm-Erklärung und Vorfallsanalyse mit Beweisbindung.

Anbieter: Anthropic, OpenAI-kompatibel, Azure OpenAI, Google Gemini und ein eigener OpenAI-kompatibler Endpunkt
(außerhalb der Appliance). Vor dem Versand werden Namen, Adressen und Kennungen pseudonymisiert (Anonymizer); die Antwort
wird lokal zurückübersetzt. Die Vorfallsanalyse verlangt zu jeder Aussage Ereignis-IDs, prüft sie lokal, führt zwei
unabhängige Durchläufe aus und markiert Widersprüche und Lücken. KI-Ergebnisse sind Hinweise, keine Beweismittel.
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

from . import sophos
from .anonymizer import Pseudonymizer
from .notify import valid_webhook
from .security import crypto

CONTEXT = "ai.key"
PROVIDERS = ("anthropic", "openai", "azure", "gemini", "custom")
PIVOT_FIELDS = ("user.name", "host.name", "source.ip", "destination.ip")
MAX_EVENTS = 150
MAX_TOKENS = 2000
_ID = re.compile(r"\bE\d{1,4}\b")
_PLACEHOLDER = re.compile(r"\b(?:HOST|USER)_\d{2,}\b|10\.250\.\d{1,3}\.\d{1,3}|fd00:250::[0-9a-f]+|02:00:00(?::[0-9a-f]{2}){3}")


class AiError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Store:
    def __init__(self, secrets_dir: Path, master_key: bytes) -> None:
        self.path = secrets_dir / "ai.json"
        self.usage_path = secrets_dir / "ai-usage.json"
        self.key = master_key

    def config(self) -> dict[str, Any]:
        c = sophos._read(self.path)
        return {"enabled": bool(c.get("enabled")), "provider": c.get("provider", "anthropic"), "model": c.get("model", ""),
                "base_url": c.get("base_url", ""), "has_key": bool(c.get("api_key")),
                "anonymize": bool(c.get("anonymize", True)), "daily_token_limit": int(c.get("daily_token_limit", 200000))}

    def api_key(self) -> str:
        blob = sophos._read(self.path).get("api_key")
        if not blob:
            return ""
        try:
            return crypto.decrypt(self.key, base64.b64decode(blob), CONTEXT)
        except (crypto.DecryptionError, ValueError) as exc:
            raise AiError("ai_secret_unreadable") from exc

    def save(self, c: dict[str, Any], api_key: str | None) -> None:
        if c["provider"] not in PROVIDERS or not 1000 <= c["daily_token_limit"] <= 10_000_000:
            raise AiError("ai_invalid_settings")
        base = c["base_url"].strip()
        if c["provider"] in ("azure", "custom", "openai") and base and not (
                valid_webhook(base) or (c["provider"] == "custom" and base.startswith(("http://", "https://")))):
            raise AiError("ai_invalid_url")
        if c["provider"] in ("azure", "custom") and c["enabled"] and not base:
            raise AiError("ai_invalid_url")
        old = sophos._read(self.path)
        # Externe Anbieter nur pseudonymisiert; nur der eigene Endpunkt darf ohne Anonymisierung arbeiten
        anonymize = True if c["provider"] != "custom" else bool(c["anonymize"])
        data = {"enabled": c["enabled"], "provider": c["provider"], "model": c["model"].strip()[:100], "base_url": base,
                "anonymize": anonymize, "daily_token_limit": c["daily_token_limit"], "api_key": old.get("api_key")}
        if api_key:
            data["api_key"] = base64.b64encode(crypto.encrypt(self.key, api_key, CONTEXT)).decode()
        sophos._write(self.path, data)

    def used_today(self) -> int:
        u = sophos._read(self.usage_path)
        return int(u.get("tokens", 0)) if u.get("day") == datetime.now(UTC).strftime("%Y-%m-%d") else 0

    def add_usage(self, tokens: int) -> None:
        sophos._write(self.usage_path, {"day": datetime.now(UTC).strftime("%Y-%m-%d"), "tokens": self.used_today() + tokens})


# ---------------------------------------------------------------- Transport

def _post(url: str, headers: dict[str, str], body: dict[str, Any], timeout: float = 90.0) -> dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers},  # noqa: S310
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 – https für externe Anbieter, siehe build_request
            return json.loads(r.read(4_000_000))
    except urllib.error.HTTPError as exc:
        raise AiError("ai_auth_failed" if exc.code in (401, 403) else "ai_request_failed") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise AiError("ai_unreachable") from exc


def build_request(cfg: dict[str, Any], key: str, system: str, user: str) -> tuple[str, dict[str, str], dict[str, Any]]:
    p, model, base = cfg["provider"], cfg["model"], cfg["base_url"].rstrip("/")
    if p == "anthropic":
        return ("https://api.anthropic.com/v1/messages", {"x-api-key": key, "anthropic-version": "2023-06-01"},
                {"model": model or "claude-sonnet-5-5", "max_tokens": MAX_TOKENS, "system": system,
                 "messages": [{"role": "user", "content": user}]})
    if p == "gemini":
        return (f"https://generativelanguage.googleapis.com/v1beta/models/{model or 'gemini-2.5-pro'}:generateContent",
                {"x-goog-api-key": key},
                {"systemInstruction": {"parts": [{"text": system}]}, "contents": [{"role": "user", "parts": [{"text": user}]}],
                 "generationConfig": {"maxOutputTokens": MAX_TOKENS, "temperature": 0}})
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    if p == "azure":
        return (f"{base}/openai/deployments/{model}/chat/completions?api-version=2024-06-01", {"api-key": key},
                {"messages": msgs, "max_tokens": MAX_TOKENS, "temperature": 0})
    url = (base or "https://api.openai.com/v1") + "/chat/completions"
    return url, ({"Authorization": f"Bearer {key}"} if key else {}), {"model": model or "gpt-4o", "messages": msgs,
                                                                      "max_tokens": MAX_TOKENS, "temperature": 0}


def parse_response(provider: str, resp: dict[str, Any]) -> tuple[str, int]:
    try:
        if provider == "anthropic":
            u = resp.get("usage", {})
            return "".join(b.get("text", "") for b in resp["content"]), int(u.get("input_tokens", 0) + u.get("output_tokens", 0))
        if provider == "gemini":
            u = resp.get("usageMetadata", {})
            return ("".join(p.get("text", "") for p in resp["candidates"][0]["content"]["parts"]),
                    int(u.get("totalTokenCount", 0)))
        return resp["choices"][0]["message"]["content"] or "", int(resp.get("usage", {}).get("total_tokens", 0))
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise AiError("ai_bad_response") from exc


Transport = Callable[[str, dict[str, str], dict[str, Any]], dict[str, Any]]


def complete(store: Store, system: str, user: str, transport: Transport = _post) -> str:
    cfg = store.config()
    if not cfg["enabled"]:
        raise AiError("ai_disabled")
    if store.used_today() >= cfg["daily_token_limit"]:
        raise AiError("ai_limit_reached")
    url, headers, body = build_request(cfg, store.api_key(), system, user)
    text, tokens = parse_response(cfg["provider"], transport(url, headers, body))
    store.add_usage(tokens or len(user) // 4)
    return text


# ---------------------------------------------------------------- Anonymisierung

def make_pseudonymizer(secrets_dir: Path, enabled: bool, known_hosts: list[str], known_users: list[str]) -> Pseudonymizer:
    p = Pseudonymizer(secrets_dir / "pseudonyms.json", known_hosts, known_users)
    if not enabled:
        p.line = lambda text: text  # type: ignore[method-assign]
    return p


def restore(text: str, p: Pseudonymizer) -> str:
    """Platzhalter in der Antwort lokal durch die Originalwerte ersetzen."""
    return _PLACEHOLDER.sub(lambda m: p.reveal(m.group(0)) or m.group(0), text)


def _restore_obj(o: Any, p: Pseudonymizer) -> Any:
    if isinstance(o, str):
        return restore(o, p)
    if isinstance(o, list):
        return [_restore_obj(x, p) for x in o]
    if isinstance(o, dict):
        return {k: _restore_obj(v, p) for k, v in o.items()}
    return o


# ---------------------------------------------------------------- Alarm-Erklärung

EXPLAIN_SYSTEM = ("Du bist ein erfahrener Security-Analyst für kleine Unternehmen. Erkläre den Alarm verständlich auf Deutsch "
                  "in höchstens 8 Sätzen und nenne 3 konkrete Handlungsempfehlungen. Erfinde keine Fakten; nutze nur die "
                  "gegebenen Angaben und sage, wenn Informationen fehlen. Namen und Adressen sind Platzhalter.")


def explain_alert(store: Store, p: Pseudonymizer, alert: dict[str, Any], test: bool = False,
                  transport: Transport = _post) -> dict[str, Any]:
    user = p.line(json.dumps({k: alert.get(k) for k in ("rule", "severity", "group", "count", "summary", "description",
                                                        "sample", "mitre")}, ensure_ascii=False))
    p.save()
    if test:
        return {"request": {"system": EXPLAIN_SYSTEM, "user": user}}
    return {"text": restore(complete(store, EXPLAIN_SYSTEM, user, transport), p),
            "disclaimer": "KI-gestützte Auswertung, zu prüfen."}


# ---------------------------------------------------------------- Vorfallsanalyse

FORENSIC_SYSTEM = (
    "Du analysierst einen IT-Sicherheitsvorfall anhand nummerierter Ereignisse [E1], [E2] ... Antworte ausschließlich mit "
    "JSON: {\"timeline\":[{\"time\":\"...\",\"statement\":\"...\",\"evidence\":[\"E3\"]}],"
    "\"initial_access\":{\"statement\":\"...\",\"evidence\":[\"E1\"]},\"scope\":[{\"statement\":\"...\",\"evidence\":[\"E5\"]}],"
    "\"gaps\":[\"...\"]}. JEDE Aussage muss auf mindestens eine vorhandene Ereignis-ID verweisen; Aussagen ohne Beleg "
    "sind verboten. Erfinde nichts. Wenn Daten fehlen, nenne die Lücke unter gaps. Namen und Adressen sind Platzhalter.")


def event_line(n: int, src: dict[str, Any]) -> str:
    g = lambda *path: _dig(src, path)  # noqa: E731
    msg = str(g("event", "original") or g("message") or "")[:300].replace("\n", " ")
    parts = [f"[E{n}]", str(src.get("@timestamp", "")), f"ds={g('event', 'dataset') or ''}", f"act={g('event', 'action') or ''}",
             f"out={g('event', 'outcome') or ''}", f"host={g('host', 'name') or ''}", f"user={g('user', 'name') or ''}",
             f"src={g('source', 'ip') or ''}", f"dst={g('destination', 'ip') or ''}"]
    return " ".join(parts) + f" msg={msg}"


def _dig(d: dict[str, Any], path: tuple[str, ...]) -> Any:
    for k in path:
        if not isinstance(d, dict):
            return None
        d = d.get(k)  # type: ignore[assignment]
    return d


def _json(text: str) -> dict[str, Any]:
    m = re.search(r"\{.*\}", text, re.S)
    try:
        data = json.loads(m.group(0)) if m else {}
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def verify(result: dict[str, Any], ids: set[str]) -> dict[str, Any]:
    """Beweisprüfung: nur Aussagen mit existierenden Ereignis-IDs bleiben; der Rest wird als Vermutung markiert."""
    def check(item: Any) -> dict[str, Any] | None:
        if not isinstance(item, dict) or not str(item.get("statement", "")).strip():
            return None
        ev = [e for e in item.get("evidence", []) if isinstance(e, str) and _ID.fullmatch(e) and e in ids]
        return {**{k: item[k] for k in ("time", "statement") if k in item}, "evidence": ev, "verified": bool(ev)}

    out: dict[str, Any] = {"timeline": [], "scope": [], "gaps": [str(g)[:300] for g in result.get("gaps", []) if g][:20],
                           "initial_access": None, "rejected": 0}
    for key in ("timeline", "scope"):
        for item in result.get(key, [])[:60] if isinstance(result.get(key), list) else []:
            c = check(item)
            if c is None:
                out["rejected"] += 1
            elif c["verified"]:
                out[key].append(c)
            else:
                out["rejected"] += 1  # ohne gültigen Beleg verworfen
    ia = check(result.get("initial_access"))
    out["initial_access"] = ia if ia and ia["verified"] else None
    return out


def analyze(store: Store, p: Pseudonymizer, events: list[dict[str, Any]], test: bool = False,
            transport: Transport = _post) -> dict[str, Any]:
    """events: _source-Dokumente in zeitlicher Reihenfolge. Zwei Durchläufe, lokale Prüfung, Rückübersetzung."""
    events = events[:MAX_EVENTS]
    ids = {f"E{i + 1}" for i in range(len(events))}
    user = "\n".join(p.line(event_line(i + 1, e)) for i, e in enumerate(events))
    p.save()
    if test:
        return {"request": {"system": FORENSIC_SYSTEM, "user": user}, "events": len(events)}
    if not events:
        return {"events": 0, "timeline": [], "scope": [], "initial_access": None, "gaps": ["Keine Ereignisse im Zeitraum."],
                "contradictions": [], "disclaimer": "KI-gestützte Auswertung, zu prüfen."}
    runs = [verify(_json(complete(store, FORENSIC_SYSTEM, user, transport)), ids) for _ in range(2)]
    first, second = runs
    a, b = first["initial_access"], second["initial_access"]
    contradictions = []
    if bool(a) != bool(b) or (a and b and set(a["evidence"]) != set(b["evidence"])):
        contradictions.append("Erstzugriff: die beiden unabhängigen Durchläufe nennen unterschiedliche Belege.")
    first["contradictions"] = contradictions
    first["events"] = len(events)
    first["disclaimer"] = "KI-gestützte Auswertung, zu prüfen. Kein Beweismittel."
    first["event_ids"] = {f"E{i + 1}": e.get("@timestamp") for i, e in enumerate(events)}
    return _restore_obj(first, p)
