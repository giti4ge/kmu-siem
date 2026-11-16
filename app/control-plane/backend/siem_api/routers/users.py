"""Benutzer- und Rollenverwaltung (nur lokale Benutzer, Spec 5.1)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from ..db import utcnow
from ..deps import Ctx, error, get_db, require, state
from ..models import MfaDevice, Role, User, UserRole
from ..schemas import (
    PasswordResetIn,
    RoleCreateIn,
    RoleOut,
    RoleUpdateIn,
    UserCreateIn,
    UserOut,
    UserUpdateIn,
)
from ..security import passwords, rbac, sessions

router = APIRouter(prefix="/api", tags=["users"])


def _roles_by_name(db: DbSession, names: list[str]) -> list[Role]:
    roles = db.scalars(select(Role).where(Role.name.in_(names))).all()
    missing = sorted(set(names) - {r.name for r in roles})
    if missing:
        raise error(status.HTTP_400_BAD_REQUEST, "unknown_role")
    return list(roles)


def _enabled_admins(db: DbSession) -> int:
    return db.scalar(
        select(func.count(User.id)).join(UserRole, UserRole.user_id == User.id).join(Role, Role.id == UserRole.role_id)
        .where(Role.name == rbac.SYSTEM_ADMIN, User.enabled.is_(True))
    ) or 0


def _get(db: DbSession, model, obj_id: int):
    obj = db.get(model, obj_id)
    if obj is None:
        raise error(status.HTTP_404_NOT_FOUND, "not_found")
    return obj


def _is_admin(user: User) -> bool:
    return any(r.name == rbac.SYSTEM_ADMIN for r in user.roles)


def _policy(password: str, user_like) -> None:
    try:
        passwords.check_policy(password, user_like.username, [user_like.display_name, user_like.email])
    except passwords.PolicyError as exc:
        raise error(status.HTTP_400_BAD_REQUEST, exc.args[0]) from exc


# --- Benutzer ---------------------------------------------------------------------
@router.get("/users", response_model=list[UserOut])
def list_users(ctx: Ctx = Depends(require("users:read")), db: DbSession = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.username)).all())


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreateIn, request: Request, ctx: Ctx = Depends(require("users:write")),
                db: DbSession = Depends(get_db)) -> User:
    if db.scalars(select(User).where(User.username == body.username)).first():
        raise error(status.HTTP_409_CONFLICT, "username_taken")
    _policy(body.password, body)
    user = User(
        username=body.username, display_name=body.display_name, email=body.email, language=body.language,
        password_hash=passwords.hash_password(body.password), must_change_password=True,
        enabled=True, totp_enabled=False, failed_logins=0, created_at=utcnow(),
    )
    user.roles = _roles_by_name(db, body.roles)
    db.add(user)
    db.commit()
    state(request).audit.append(db, actor=ctx.user.username, action="user.create", target=user.username,
                                ip=ctx.ip, details={"roles": sorted(body.roles)})
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdateIn, request: Request, ctx: Ctx = Depends(require("users:write")),
                db: DbSession = Depends(get_db)) -> User:
    user = _get(db, User, user_id)
    changes = body.model_dump(exclude_unset=True)
    was_admin = _is_admin(user) and user.enabled
    # Sich selbst deaktivieren oder die Admin-Rolle entziehen ist nicht möglich (Aussperren)
    if user.id == ctx.user.id and (body.enabled is False or (
            was_admin and body.roles is not None and rbac.SYSTEM_ADMIN not in body.roles)):
        raise error(status.HTTP_409_CONFLICT, "cannot_demote_self")
    for key in ("display_name", "email", "language", "enabled"):
        if key in changes and changes[key] is not None:
            setattr(user, key, changes[key])
    if body.roles is not None:
        user.roles = _roles_by_name(db, body.roles)
    db.flush()
    if was_admin and _enabled_admins(db) == 0:
        db.rollback()
        raise error(status.HTTP_409_CONFLICT, "last_admin")
    if body.enabled is False:
        sessions.revoke_user_sessions(db, user.id)
    db.commit()
    state(request).audit.append(db, actor=ctx.user.username, action="user.update", target=user.username,
                                ip=ctx.ip, details={k: v for k, v in changes.items() if v is not None})
    return user


@router.post("/users/{user_id}/reset-password", response_model=UserOut)
def reset_password(user_id: int, body: PasswordResetIn, request: Request,
                   ctx: Ctx = Depends(require("users:write")), db: DbSession = Depends(get_db)) -> User:
    user = _get(db, User, user_id)
    _policy(body.new_password, user)
    user.password_hash = passwords.hash_password(body.new_password)
    user.must_change_password = True
    user.failed_logins = 0
    user.locked_until = None
    sessions.revoke_user_sessions(db, user.id)
    db.commit()
    state(request).audit.append(db, actor=ctx.user.username, action="user.reset_password", target=user.username,
                                ip=ctx.ip)
    return user


@router.post("/users/{user_id}/reset-mfa", response_model=UserOut)
def reset_mfa(user_id: int, request: Request, ctx: Ctx = Depends(require("users:write")),
              db: DbSession = Depends(get_db)) -> User:
    user = _get(db, User, user_id)
    if user.id == ctx.user.id:
        raise error(status.HTTP_409_CONFLICT, "cannot_reset_own_mfa")
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_step = None
    db.query(MfaDevice).filter_by(user_id=user.id).delete()
    sessions.revoke_user_sessions(db, user.id)
    db.commit()
    state(request).audit.append(db, actor=ctx.user.username, action="user.reset_mfa", target=user.username,
                                ip=ctx.ip)
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, request: Request, ctx: Ctx = Depends(require("users:write")),
                db: DbSession = Depends(get_db)) -> Response:
    user = _get(db, User, user_id)
    if user.id == ctx.user.id:
        raise error(status.HTTP_409_CONFLICT, "cannot_delete_self")
    was_admin = _is_admin(user) and user.enabled
    name = user.username
    db.delete(user)
    db.flush()
    if was_admin and _enabled_admins(db) == 0:
        db.rollback()
        raise error(status.HTTP_409_CONFLICT, "last_admin")
    db.commit()
    state(request).audit.append(db, actor=ctx.user.username, action="user.delete", target=name, ip=ctx.ip)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Rollen -------------------------------------------------------------------------
@router.get("/permissions", response_model=list[str])
def list_permissions(ctx: Ctx = Depends(require("users:read"))) -> list[str]:
    return list(rbac.PERMISSIONS)


@router.get("/roles", response_model=list[RoleOut])
def list_roles(ctx: Ctx = Depends(require("users:read")), db: DbSession = Depends(get_db)) -> list[Role]:
    return list(db.scalars(select(Role).order_by(Role.builtin.desc(), Role.name)).all())


def _validated(perms: list[str]) -> list[str]:
    try:
        return rbac.validate_permissions(perms)
    except ValueError as exc:
        raise error(status.HTTP_400_BAD_REQUEST, "unknown_permission") from exc


@router.post("/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
def create_role(body: RoleCreateIn, request: Request, ctx: Ctx = Depends(require("users:write")),
                db: DbSession = Depends(get_db)) -> Role:
    if db.scalars(select(Role).where(Role.name == body.name)).first():
        raise error(status.HTTP_409_CONFLICT, "role_exists")
    role = Role(name=body.name, description=body.description, builtin=False, mfa_required=body.mfa_required,
                permissions=_validated(body.permissions), data_scope=body.data_scope.model_dump())
    db.add(role)
    db.commit()
    state(request).audit.append(db, actor=ctx.user.username, action="role.create", target=role.name, ip=ctx.ip,
                                details={"permissions": role.permissions, "data_scope": role.data_scope})
    return role


@router.patch("/roles/{role_id}", response_model=RoleOut)
def update_role(role_id: int, body: RoleUpdateIn, request: Request, ctx: Ctx = Depends(require("users:write")),
                db: DbSession = Depends(get_db)) -> Role:
    role = _get(db, Role, role_id)
    if role.builtin:
        raise error(status.HTTP_409_CONFLICT, "builtin_role")
    if body.description is not None:
        role.description = body.description
    if body.mfa_required is not None:
        role.mfa_required = body.mfa_required
    if body.permissions is not None:
        role.permissions = _validated(body.permissions)
    if body.data_scope is not None:
        role.data_scope = body.data_scope.model_dump()
    db.commit()
    state(request).audit.append(db, actor=ctx.user.username, action="role.update", target=role.name, ip=ctx.ip,
                                details={"permissions": role.permissions, "data_scope": role.data_scope,
                                         "mfa_required": role.mfa_required})
    return role


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(role_id: int, request: Request, ctx: Ctx = Depends(require("users:write")),
                db: DbSession = Depends(get_db)) -> Response:
    role = _get(db, Role, role_id)
    if role.builtin:
        raise error(status.HTTP_409_CONFLICT, "builtin_role")
    if db.scalar(select(func.count()).select_from(UserRole).where(UserRole.role_id == role.id)):
        raise error(status.HTTP_409_CONFLICT, "role_in_use")
    name = role.name
    db.delete(role)
    db.commit()
    state(request).audit.append(db, actor=ctx.user.username, action="role.delete", target=name, ip=ctx.ip)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
