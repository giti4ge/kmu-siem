"""KI-Bridge: Einstellungen, Alarm-Erklärung, Vorfallsanalyse (Testmodus zeigt die gesendete Anfrage)."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import ai
from ..deps import Ctx, error, get_db, require, state
from ..opensearch import OpenSearchUnavailable
from .alerts import _row
from .logs import client_for

router = APIRouter(tags=["ai"], prefix="/api/ai")


class SettingsIn(BaseModel):
    enabled: bool = False
    provider: Literal["anthropic", "openai", "azure", "gemini", "custom"] = "anthropic"
    model: str = Field("", max_length=100)
    base_url: str = Field("", max_length=300)
    api_key: str | None = Field(None, max_length=400)
    anonymize: bool = True
    daily_token_limit: int = Field(200000, ge=1000, le=10_000_000)


class ExplainIn(BaseModel):
    alert_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    index: str = Field(pattern=r"^siem-alerts-\d{4}\.\d{2}\.\d{2}$")
    test: bool = False


class ForensicsIn(BaseModel):
    field: Literal["user.name", "host.name", "source.ip", "destination.ip"]
    value: str = Field(min_length=1, max_length=200)
    hours: int = Field(24, ge=1, le=720)
    test: bool = False


def _store(request: Request) -> ai.Store:
    return request.app.state.ai_store


def _view(request: Request) -> dict[str, Any]:
    st = _store(request)
    return {"config": st.config(), "used_today": st.used_today()}


@router.get("")
def get_settings(request: Request, ctx: Ctx = Depends(require("system:read"))) -> dict:
    return _view(request)


@router.put("")
def put_settings(body: SettingsIn, request: Request, db: DbSession = Depends(get_db),
                 ctx: Ctx = Depends(require("system:write"))) -> dict:
    try:
        _store(request).save(body.model_dump(exclude={"api_key"}), body.api_key or None)
    except ai.AiError as exc:
        raise error(400, exc.code) from exc
    except OSError as exc:
        raise error(503, "ai_storage_unavailable") from exc
    state(request).audit.append(db, actor=ctx.user.username, action="ai.settings", target=body.provider, ip=ctx.ip,
                                details={"enabled": body.enabled, "key_changed": bool(body.api_key),
                                         "anonymize": body.anonymize})
    return _view(request)


def _run(request: Request, db: DbSession, ctx: Ctx, action: str, target: str, fn) -> dict:
    try:
        out = fn()
    except ai.AiError as exc:
        state(request).audit.append(db, actor=ctx.user.username, action=action, target=target, outcome="failure",
                                    ip=ctx.ip, details={"error": exc.code})
        raise error(502 if exc.code not in ("ai_disabled", "ai_limit_reached") else 409, exc.code) from exc
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    state(request).audit.append(db, actor=ctx.user.username, action=action, target=target, ip=ctx.ip,
                                details={"external": _store(request).config()["provider"]})  # nie Inhalte
    return out


@router.post("/explain")
def explain(body: ExplainIn, request: Request, db: DbSession = Depends(get_db),
            ctx: Ctx = Depends(require("alerts:read"))) -> dict:
    st = _store(request)
    secrets = state(request).settings.secrets_dir

    def go() -> dict:
        doc = client_for(request).request("GET", f"/{body.index}/_doc/{body.alert_id}")
        if not doc or not doc.get("found"):
            raise error(404, "alert_not_found")
        alert = _row(doc)
        sample_hosts = [h for h in (str(alert.get("group") or ""),) if h]
        p = ai.make_pseudonymizer(secrets, st.config()["anonymize"], sample_hosts, [])
        return ai.explain_alert(st, p, alert, body.test, reveal=not request.app.state.privacy.masked_for(ctx.permissions))

    return _run(request, db, ctx, "ai.explain", body.alert_id, go)


@router.post("/forensics")
def forensics(body: ForensicsIn, request: Request, db: DbSession = Depends(get_db),
              ctx: Ctx = Depends(require("logs:read"))) -> dict:
    st = _store(request)
    secrets = state(request).settings.secrets_dir

    def go() -> dict:
        q = {"size": ai.MAX_EVENTS, "sort": [{"@timestamp": "asc"}], "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": f"now-{body.hours}h"}}}, {"term": {body.field: body.value}}],
            "must_not": [{"term": {"siem.category": "unparsed"}}, {"term": {"siem.category": "audit"}}]}}}
        resp = client_for(request).search("siem-*", q)
        events = [h.get("_source", {}) for h in resp.get("hits", {}).get("hits", [])]
        hosts = sorted({str(e["host"]["name"]) for e in events if e.get("host", {}).get("name")})
        users = sorted({str(e["user"]["name"]) for e in events if e.get("user", {}).get("name")})
        p = ai.make_pseudonymizer(secrets, st.config()["anonymize"], hosts, users)
        return ai.analyze(st, p, events, body.test, reveal=not request.app.state.privacy.masked_for(ctx.permissions))

    return _run(request, db, ctx, "ai.forensics", f"{body.field}={body.value}"[:100], go)
