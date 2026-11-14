"""SNMP-Zugangsdaten für Trap-Empfang (v2c-Communities, v3-Benutzer)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import snmp_config
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["snmp"], prefix="/api/snmp")


class V3User(BaseModel):
    user: str = Field(max_length=32)
    auth_proto: Literal["sha", "sha256"]
    auth_key: str | None = Field(default=None, max_length=128)
    priv_proto: Literal["none", "aes128", "aes256"]
    priv_key: str | None = Field(default=None, max_length=128)
    engine_id: str | None = Field(default=None, max_length=66)


class Target(BaseModel):
    ip: str = Field(max_length=45)
    name: str = Field(default="", max_length=64)
    version: Literal["v2c", "v3"]
    user: str | None = Field(default=None, max_length=32)
    community: str | None = Field(default=None, max_length=64)
    category: Literal["network", "infra"] = "network"


class SnmpIn(BaseModel):
    # None = Abfrageziele unverändert lassen
    targets: list[Target] | None = Field(default=None, max_length=500)
    # None = vorhandene Communities beibehalten; Liste = ersetzen
    communities: list[str] | None = Field(default=None, max_length=50)
    v3_users: list[V3User] = Field(default_factory=list, max_length=50)


@router.get("")
def get_snmp(request: Request, ctx: Ctx = Depends(require("sources:read"))) -> dict:
    return snmp_config.view(state(request).settings.secrets_dir)


@router.put("")
def put_snmp(body: SnmpIn, request: Request, db: DbSession = Depends(get_db),
             ctx: Ctx = Depends(require("sources:write"))) -> dict:
    st = state(request)
    try:
        snmp_config.save(st.settings.secrets_dir, st.keys.master_key, body.communities,
                         [u.model_dump() for u in body.v3_users],
                         None if body.targets is None else [t.model_dump() for t in body.targets])
    except snmp_config.SnmpConfigError as exc:
        raise error(400, exc.code) from exc
    except OSError as exc:
        raise error(503, "snmp_storage_unavailable") from exc
    st.audit.append(db, actor=ctx.user.username, action="snmp.settings", target="traps", ip=ctx.ip,
                    details={"v3_users": [u.user for u in body.v3_users],
                             "communities_replaced": body.communities is not None,
                             "targets": None if body.targets is None else [t.ip for t in body.targets][:100]})
    return snmp_config.view(st.settings.secrets_dir)
