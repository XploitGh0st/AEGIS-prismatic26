"""
AEGIS Database — async SQLAlchemy engine and session factory.

Supports:
- PostgreSQL (production) via asyncpg
- SQLite (local dev/testing) via aiosqlite

Note: init_db() uses a synchronous engine for table creation to avoid
the greenlet dependency (which may be blocked by enterprise Application
Control policies on Windows).
"""

from __future__ import annotations

from sqlalchemy import MetaData, create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

# Naming convention so Alembic auto-generates sensible constraint names
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""

    metadata = MetaData(naming_convention=convention)


def _get_sync_url() -> str:
    """Get a synchronous database URL for table creation."""
    db_url = settings.database_url
    if db_url.startswith("sqlite"):
        # Strip any async prefix
        return db_url.replace("+aiosqlite", "")
    # PostgreSQL: use psycopg sync driver
    return settings.sync_database_url


def _build_engine():
    """
    Build the async engine based on the configured DATABASE_URL.

    Falls back to SQLite (aiosqlite) when the URL starts with 'sqlite'.
    """
    db_url = settings.database_url

    # SQLite path (local dev without Docker)
    if db_url.startswith("sqlite"):
        # Ensure async prefix
        if "+aiosqlite" not in db_url:
            db_url = db_url.replace("sqlite://", "sqlite+aiosqlite://", 1)

        return create_async_engine(
            db_url,
            echo=settings.app_env == "development",
            connect_args={"check_same_thread": False},
        )

    # PostgreSQL path (default)
    async_url = settings.async_database_url
    return create_async_engine(
        async_url,
        echo=settings.app_env == "development",
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )


engine = _build_engine()

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncSession:
    """Dependency that yields an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Create all tables using a synchronous engine.

    Uses sync SQLAlchemy to avoid the greenlet dependency, which may be
    blocked by Windows Application Control policies.
    """
    sync_url = _get_sync_url()
    sync_engine = create_engine(sync_url, echo=False)
    Base.metadata.create_all(sync_engine)
    sync_engine.dispose()


async def close_db() -> None:
    """Dispose of the engine connection pool."""
    await engine.dispose()
