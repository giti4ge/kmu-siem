"""Web-Zertifikat: eigenes Zertifikat per PFX-Upload einspielen, Rückfall auf vorheriges bzw. Appliance-Zertifikat.

Die PFX-Datei wird hier entschlüsselt und in PEM (Kette + unverschlüsselter Schlüssel) umgewandelt; siem-hostd prüft
(Schlüssel passt, nicht abgelaufen), sichert das bisherige Zertifikat, startet den Proxy neu und stellt es automatisch
wieder her, falls der Proxy mit dem neuen Zertifikat nicht gesund wird.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi import APIRouter, Depends, Request
from pydantic import Field
from sqlalchemy.orm import Session as DbSession

from .. import hostd
from ..deps import Ctx, error, get_db, require, state
from ..schemas import Strict

router = APIRouter(tags=["tls"], prefix="/api/tls")
MAX_PFX = 100_000


class PfxIn(Strict):
    pfx_b64: str = Field(min_length=1, max_length=MAX_PFX * 2)
    password: str = Field("", max_length=256)


def pfx_to_pem(data: bytes, password: str) -> tuple[str, str]:
    """PFX → (Zertifikatskette PEM: Server zuerst, Schlüssel PKCS#8 PEM)."""
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, password.encode() if password else None)
    except (ValueError, TypeError):
        raise error(400, "tls_bad_pfx") from None
    if key is None or cert is None:
        raise error(400, "tls_pfx_incomplete")
    chain = [cert]
    pool = list(extra or [])
    while pool:  # Zwischenzertifikate in Ausstellerreihenfolge anhängen; übrige (z. B. fremde Root) werden ausgelassen
        nxt = next((c for c in pool if c.subject == chain[-1].issuer and c.subject != chain[-1].subject), None)
        if nxt is None:
            break
        chain.append(nxt)
        pool.remove(nxt)
    pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    return pem, key_pem


def _call(request: Request, ctx: Ctx, action: str, params: dict[str, Any] | None = None) -> Any:
    try:
        return hostd.call(state(request).settings.hostd_socket, action, params or {}, actor=f"{ctx.user.username}@web")
    except hostd.HostdUnavailable:
        raise error(503, "hostd_unavailable") from None
    except hostd.HostdRejected as exc:
        msg = str(exc)
        key = "tls_key_mismatch" if "passt nicht" in msg else "tls_expired" if "abgelaufen" in msg else \
            "tls_no_previous" if "Kein früheres" in msg else "tls_invalid"
        raise error(400, key) from None


@router.get("")
def status(request: Request, ctx: Ctx = Depends(require("system:read"))) -> Any:
    return _call(request, ctx, "tls.status")


@router.post("/pfx")
def install_pfx(body: PfxIn, request: Request, db: DbSession = Depends(get_db),
                ctx: Ctx = Depends(require("system:write"))) -> Any:
    try:
        data = base64.b64decode(body.pfx_b64, validate=True)
    except (binascii.Error, ValueError):
        raise error(400, "tls_bad_pfx") from None
    if len(data) > MAX_PFX:
        raise error(400, "tls_bad_pfx")
    chain, key = pfx_to_pem(data, body.password)
    res = _call(request, ctx, "tls.install", {"chain_pem": chain, "key_pem": key})
    state(request).audit.append(db, actor=ctx.user.username, action="tls.install", target=res.get("fingerprint", ""),
                                ip=ctx.ip, details={"subject": res.get("subject", "")})
    return res


@router.post("/rollback")
def rollback(request: Request, db: DbSession = Depends(get_db), ctx: Ctx = Depends(require("system:write"))) -> Any:
    res = _call(request, ctx, "tls.rollback")
    state(request).audit.append(db, actor=ctx.user.username, action="tls.rollback", target="web", ip=ctx.ip)
    return res


@router.post("/reset")
def reset(request: Request, db: DbSession = Depends(get_db), ctx: Ctx = Depends(require("system:write"))) -> Any:
    res = _call(request, ctx, "tls.reset")
    state(request).audit.append(db, actor=ctx.user.username, action="tls.reset", target="web", ip=ctx.ip)
    return res
