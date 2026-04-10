"""
Cross-dialect type compatibility for SQLAlchemy.

Provides types that work on both PostgreSQL and SQLite:
- PortableJSON → JSONB on PostgreSQL, JSON on SQLite
- PortableArray → ARRAY on PostgreSQL, JSON-encoded list on SQLite
- PortableUUID → UUID on PostgreSQL, CHAR(36) on SQLite
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy import JSON, String, TypeDecorator, types
from sqlalchemy.engine import Dialect


class PortableJSON(TypeDecorator):
    """JSONB on PostgreSQL, JSON on SQLite."""
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect):
        if dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import JSONB
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class PortableArray(TypeDecorator):
    """
    ARRAY on PostgreSQL, JSON-encoded list on SQLite.
    Stores as JSON text in SQLite, native ARRAY in PostgreSQL.
    """
    impl = JSON
    cache_ok = True

    def __init__(self, item_type=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.item_type = item_type

    def load_dialect_impl(self, dialect: Dialect):
        if dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import ARRAY
            return dialect.type_descriptor(
                ARRAY(self.item_type or String(100))
            )
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value  # Native ARRAY handling
        return value  # JSON serialization handled by impl

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, str):
            return json.loads(value)
        return value


class PortableUUID(TypeDecorator):
    """UUID on PostgreSQL, CHAR(36) on SQLite."""
    impl = String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect):
        if dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import UUID as PG_UUID
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value  # Native UUID
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)
