"""FastAPI-Anwendung (create_app) – Start: uvicorn siem_api.main:app."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import __version__
from . import active_response as ar_mod
from . import ai as ai_mod
from . import alerts as alerts_mod
from . import archive as archive_mod
from . import archive_restore as archive_restore_mod
from . import fortigate as fortigate_mod
from . import maintenance as maintenance_mod
from . import notify as notify_mod
from . import privacy as privacy_mod
from . import updates as updates_mod
from .audit import AuditLog
from .config import Settings, get_settings
from .db import Database, migrate
from .deps import AppState
from .opensearch import OpenSearchClient
from .routers import (
    ai as ai_router,
)
from .routers import (
    alerts as alerts_router,
)
from .routers import ar as ar_router
from .routers import archive as archive_router
from .routers import (
    assets,
    audit,
    auth,
    changes,
    devices,
    linux,
    logs,
    retention,
    snmp,
    switches,
    system,
    users,
    wec,
)
from .routers import dashboard as dashboard_router
from .routers import forensic_export as forensic_export_router
from .routers import (
    fortigate as fortigate_router,
)
from .routers import maintenance as maintenance_router
from .routers import notify as notify_router
from .routers import reports as reports_router
from .routers import setup as setup_router
from .routers import sophos as sophos_router
from .routers import support as support_router
from .routers import updates as updates_router
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
    forti_store = fortigate_mod.Store(settings.secrets_dir, keys.master_key)
    forti_poller = fortigate_mod.Poller(forti_store)

    db_file = database.engine.url.database if database.engine.url.get_backend_name() == "sqlite" else None

    def maint_report(action: str, outcome: str, details: dict) -> None:
        with database.sessionmaker() as sess:
            app.state.siem.audit.append(sess, actor="system", action=action, target="maintenance",
                                        outcome=outcome, ip="", details=details)

    alert_store = alerts_mod.RuleStore(settings.secrets_dir / "rules.json")
    notify_store = notify_mod.Store(settings.secrets_dir, keys.master_key)
    ai_store = ai_mod.Store(settings.secrets_dir, keys.master_key)
    update_store = updates_mod.Store(settings.secrets_dir, keys.master_key)
    privacy = privacy_mod.Privacy(settings.secrets_dir, keys.master_key)
    ar_store = ar_mod.Store(settings.secrets_dir, keys.master_key)
    ar_expirer = ar_mod.Expirer(ar_store, forti_store)

    def on_alert(alert: dict) -> None:
        notify_mod.dispatch(notify_store, alert)
        ip = ar_mod.auto_candidate(alert)
        if ip and ar_store.config()["auto"]:
            try:
                entry = ar_mod.block(ar_store, forti_store, ip, None, alert["rule"]["name"], "automatisch", auto=True)
                maint_report("ar.auto_block", "success", {"ip": entry["ip"], "until": entry["until"]})
            except ar_mod.ARError as exc:
                maint_report("ar.auto_block", "failure", {"ip": ip, "error": exc.code})

    alert_engine = alerts_mod.Engine(OpenSearchClient(settings.opensearch_url, settings.secrets_dir), alert_store,
                                     notify=on_alert)

    maintenance = maintenance_mod.Scheduler(
        db_path=Path(db_file) if db_file else None, backup_dir=settings.backup_dir,
        client=OpenSearchClient(settings.opensearch_url, settings.secrets_dir), report=maint_report)

    archive_obj = archive_mod.Archive(settings.archive_dir,
                                      archive_mod.load_or_create_key(settings.secrets_dir / "archive-ed25519.pem"))
    archive_retention = archive_restore_mod.RetentionStore(settings.backup_dir / "archive-retention.json")
    archive_restorer = archive_restore_mod.Restorer(
        archive_obj, OpenSearchClient(settings.opensearch_url, settings.secrets_dir, timeout=60),
        settings.backup_dir / "archive-restore.json", report=maint_report)
    archive_worker = archive_mod.Worker(archive_obj, settings.backup_dir / "archive.json", report=maint_report,
                                        retention=archive_retention, restorer=archive_restorer)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Sophos-Abruf im Hintergrund (nur wenn aktiviert); in Tests per SIEM_SOPHOS_POLL=0 abschaltbar
        if os.environ.get("SIEM_SOPHOS_POLL", "1") != "0":
            poller.start()
            forti_poller.start()
            maintenance.start()
            archive_worker.start()
            alert_engine.start()
            ar_expirer.start()
        yield
        poller.stop.set()
        poller.trigger.set()
        forti_poller.stop.set()
        forti_poller.trigger.set()
        maintenance.stop.set()
        archive_worker.stop.set()
        alert_engine.stop.set()
        ar_expirer.stop.set()

    app = FastAPI(title="KMU-SIEM API", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.sophos_store = sophos_store
    app.state.sophos_poller = poller
    app.state.forti_store = forti_store
    app.state.forti_poller = forti_poller
    app.state.maintenance = maintenance
    app.state.archive_worker = archive_worker
    app.state.alert_store = alert_store
    app.state.notify_store = notify_store
    app.state.ai_store = ai_store
    app.state.update_store = update_store
    app.state.privacy = privacy
    app.state.ar_store = ar_store
    app.state.alert_engine = alert_engine
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
                   logs.router, linux.router, retention.router, sophos_router.router, changes.router,
                   snmp.router, maintenance_router.router, alerts_router.router, forensic_export_router.router, archive_router.router, support_router.router, updates_router.router, setup_router.router, reports_router.router, ar_router.router, ai_router.router, dashboard_router.router, notify_router.router, switches.router, assets.router, fortigate_router.router):
        app.include_router(router)
    return app


def __getattr__(name: str):
    # "app" erst bei Bedarf erzeugen (Import ohne Seiteneffekte für Tests/Werkzeuge)
    if name == "app":
        return create_app()
    raise AttributeError(name)
