"""FastAPI-Anwendung (create_app) – Start: uvicorn siem_api.main:app."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import __version__
from .audit import AuditLog
from .config import Settings, get_settings
from .db import Database, migrate
from .deps import AppState
from .routers import audit, auth, changes, devices, linux, logs, retention, snmp, system, users, wec
from .routers import sophos as sophos_router
from .security import rbac
from .security.keys import KeyRing
from .sophos import Poller, Store


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    database = Database(settings.db_url)
    migrate(database.engine)
    keys = KeyRing(settings.secrets_dir)
    with database.sessionmaker() as s:
        rbac.seed_roles(s)

    # Keine öffentliche API-Dokumentation (Angriffsfläche); intern über Tests/OpenAPI-Export
    sophos_store = Store(settings.secrets_dir, keys.master_key)
    poller = Poller(sophos_store)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Sophos-Abruf im Hintergrund (nur wenn aktiviert); in Tests per SIEM_SOPHOS_POLL=0 abschaltbar
        if os.environ.get("SIEM_SOPHOS_POLL", "1") != "0":
            poller.start()
        yield
        poller.stop.set()
        poller.trigger.set()

    app = FastAPI(title="KMU-SIEM API", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.sophos_store = sophos_store
    app.state.sophos_poller = poller
    app.state.siem = AppState(settings=settings, db=database, keys=keys,
                              audit=AuditLog(keys.audit_key, keys.audit_head_file))

    @app.middleware("http")
    async def no_store(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Feldnamen und Fehlerart, aber keine Eingabewerte zurückgeben (keine Kennwörter im Echo)
        fields = [{"loc": list(e.get("loc", ())), "type": e.get("type")} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": {"error": "validation_failed", "fields": fields}})

    for router in (system.router, auth.router, users.router, audit.router, wec.router, devices.router,
                   logs.router, linux.router, retention.router, sophos_router.router, changes.router, snmp.router):
        app.include_router(router)
    return app


def __getattr__(name: str):
    # "app" erst bei Bedarf erzeugen (Import ohne Seiteneffekte für Tests/Werkzeuge)
    if name == "app":
        return create_app()
    raise AttributeError(name)
