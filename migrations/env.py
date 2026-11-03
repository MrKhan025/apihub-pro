"""
Alembic migration environment for API-Hub-Pro (apihub-pro).
Supports both SQLAlchemy/Alembic CLI execution and built-in migration runner fallback.
"""

from __future__ import annotations

from apihub.config import settings
from apihub.database import db


def run_migrations_offline() -> dict:
    """Run migrations in offline mode or via built-in runner."""
    return db.run_migrations("head")


def run_migrations_online() -> dict:
    """Run migrations in online mode using configured DATABASE_URL."""
    try:
        from alembic import context  # type: ignore
        from sqlalchemy import engine_from_config, pool  # type: ignore

        config = context.config
        config.set_main_option("sqlalchemy.url", settings.database_url)
        connectable = engine_from_config(
            config.get_section(config.config_ini_section, {}),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
        with connectable.connect() as connection:
            context.configure(connection=connection, target_metadata=None)
            with context.begin_transaction():
                context.run_migrations()
    except Exception:
        pass
    return db.run_migrations("head")
