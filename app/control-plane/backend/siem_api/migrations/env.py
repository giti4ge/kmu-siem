"""Alembic-Umgebung: Verbindung wird von db.migrate() übergeben."""

from alembic import context

from siem_api.models import Base

target_metadata = Base.metadata
connection = context.config.attributes.get("connection")
if connection is None:  # pragma: no cover - nur bei direktem Alembic-Aufruf
    raise RuntimeError("Migrationen bitte über siem_api.db.migrate() ausführen")

context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
with context.begin_transaction():
    context.run_migrations()
