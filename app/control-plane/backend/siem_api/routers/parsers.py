"""Parser-Editor: eigene Regeln für nicht erkannte Quellen."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import custom_parsers as cp
from .. import hostd
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["parsers"], prefix="/api/parsers")
log = logging.getLogger(__name__)


class RuleIn(BaseModel):
    id: str = Field(max_length=32)
    name: str = Field(default="", max_length=64)
    program: str = Field(default="", max_length=48)
    regex: str = Field(max_length=cp.MAX_REGEX)
    category: str = Field(max_length=16)
    fields: dict[str, str] = Field(default_factory=dict, max_length=12)
    action: str = Field(default="", max_length=48)
    enabled: bool = True


class RulesIn(BaseModel):
    rules: list[RuleIn] = Field(max_length=cp.MAX_RULES)


class TestIn(BaseModel):
    rule: RuleIn
    samples: list[str] = Field(max_length=50)


@router.get("")
def get_rules(request: Request, ctx: Ctx = Depends(require("sources:read"))) -> dict[str, Any]:
    return {"rules": request.app.state.parsers.rules(), "categories": cp.CATEGORIES, "fields": sorted(cp.FIELDS)}


@router.put("")
def put_rules(body: RulesIn, request: Request, db: DbSession = Depends(get_db),
              ctx: Ctx = Depends(require("sources:write"))) -> dict[str, Any]:
    st = state(request)
    try:
        rules = request.app.state.parsers.save([r.model_dump() for r in body.rules])
    except cp.ParserError as exc:
        raise error(422, exc.code) from None
    except OSError:
        raise error(503, "wec_storage_unavailable") from None
    applied = True
    try:
        hostd.call(st.settings.hostd_socket, "vector.restart", {}, actor=f"{ctx.user.username}@web")
    except (hostd.HostdUnavailable, hostd.HostdRejected):
        log.warning("Vector konnte nicht neu gestartet werden")
        applied = False
    st.audit.append(db, actor=ctx.user.username, action="parsers.save", target="custom", ip=ctx.ip,
                    details={"rules": [r["id"] for r in rules], "applied": applied})
    return {"rules": rules, "applied": applied}


@router.post("/test")
def test_rule(body: TestIn, ctx: Ctx = Depends(require("sources:read"))) -> list[dict[str, Any]]:
    try:
        return cp.test_rule(body.rule.model_dump(), body.samples, body.rule.program)
    except cp.ParserError as exc:
        raise error(422, exc.code) from None
