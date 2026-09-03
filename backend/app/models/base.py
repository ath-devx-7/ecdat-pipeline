"""Declarative base and the cross-dialect column types.

Postgres 16 is the target store. The SQLite variants exist so the test suite and
``alembic upgrade head`` can run without a database server; nothing in the
application depends on SQLite.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, mapped_column


class Base(DeclarativeBase):
    pass


#: ``jsonb`` on Postgres, plain JSON elsewhere.
JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

#: ``timestamptz`` on Postgres.
TIMESTAMPTZ = sa.DateTime(timezone=True)


def pg_enum(python_enum: type[enum.Enum], name: str) -> sa.Enum:
    """A native Postgres ENUM storing the member *values*, not their names."""
    return sa.Enum(
        python_enum,
        name=name,
        values_callable=lambda e: [member.value for member in e],
        native_enum=True,
    )


def uuid_pk() -> Any:
    return mapped_column(sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


def created_at_col() -> Any:
    # Aware UTC, the same clock `completed_at` is stamped with in the runner. A
    # naive local default beside an aware UTC completion put two zones on one
    # row, which the PDF report was the first thing to print side by side.
    return mapped_column(
        TIMESTAMPTZ,
        nullable=False,
        server_default=sa.func.now(),
        default=lambda: datetime.now(timezone.utc),
    )
