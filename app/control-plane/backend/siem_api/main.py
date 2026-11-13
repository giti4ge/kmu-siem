"""FastAPI-Anwendung (create_app) – Start: uvicorn siem_api.main:app."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import __version__
from .audit import AuditLog
from .config import Settings, get_settings
from .db import Database, migrate
from .deps import AppState
from .routers import audit, auth, system, users
from .security import rbac
from .security.keys import KeyRing


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    database = Database(settings.db_url)
    migrate(database.engine)
    keys = KeyRing(settings.secrets_dir)
    with database.sessionmaker() as s:
        rbac.seed_roles(s)

    # Keine öffentliche API-Dokumentation (Angriffsfläche); intern über Tests/OpenAPI-Export
    app = FastAPI(title="KMU-SIEM API", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
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

    for router in (system.router, auth.router, users.router, audit.router):
        app.include_router(router)
    return app


def __getattr__(name: str):
    # "app" erst bei Bedarf erzeugen (Import ohne Seiteneffekte für Tests/Werkzeuge)
    if name == "app":
        return create_app()
    raise AttributeError(name)
