"""Ein-/Ausgabeschemata (Pydantic v2). Alle Eingaben sind streng validiert."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

USERNAME_PATTERN = r"^[a-z][a-z0-9._-]{1,63}$"
ROLENAME_PATTERN = r"^[a-z][a-z0-9-]{1,63}$"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginIn(Strict):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()


class CodeIn(Strict):
    code: str = Field(min_length=6, max_length=8)


class PasswordChangeIn(Strict):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class PasswordResetIn(Strict):
    new_password: str = Field(min_length=1, max_length=256)


class RoleRef(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    display_name: str
    email: str
    language: str
    enabled: bool
    totp_enabled: bool
    must_change_password: bool
    last_login_at: datetime | None
    roles: list[RoleRef]


class MeOut(BaseModel):
    user: UserOut
    stage: str
    permissions: list[str]
    csrf_token: str


class UserCreateIn(Strict):
    username: str = Field(pattern=USERNAME_PATTERN)
    display_name: str = Field(default="", max_length=128)
    email: EmailStr | Literal[""] = ""
    language: Literal["de", "en"] = "de"
    password: str = Field(min_length=1, max_length=256)
    roles: list[str] = Field(default_factory=list, max_length=20)


class UserUpdateIn(Strict):
    display_name: str | None = Field(default=None, max_length=128)
    email: EmailStr | Literal[""] | None = None
    language: Literal["de", "en"] | None = None
    enabled: bool | None = None
    roles: list[str] | None = Field(default=None, max_length=20)


class RoleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    builtin: bool
    mfa_required: bool
    permissions: list[str]
    data_scope: dict


class DataScope(Strict):
    categories: list[str] = Field(default_factory=list, max_length=50)
    masked_fields: list[str] = Field(default_factory=list, max_length=100)


class RoleCreateIn(Strict):
    name: str = Field(pattern=ROLENAME_PATTERN)
    description: str = Field(default="", max_length=255)
    mfa_required: bool = False
    permissions: list[str] = Field(default_factory=list, max_length=100)
    data_scope: DataScope = Field(default_factory=DataScope)


class RoleUpdateIn(Strict):
    description: str | None = Field(default=None, max_length=255)
    mfa_required: bool | None = None
    permissions: list[str] | None = Field(default=None, max_length=100)
    data_scope: DataScope | None = None


class TotpSetupOut(BaseModel):
    secret: str
    uri: str


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    ts: str
    actor: str
    action: str
    target: str
    outcome: str
    ip: str
    details: str


class AuditVerifyOut(BaseModel):
    ok: bool
    entries: int
    first_bad_seq: int | None
    reason: str | None
