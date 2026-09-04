"""source_type: upload

A browser folder upload is its own source type, not a `folder` whose path
happens to be inside the work root. The difference is ownership: `folder` reads
a tree the user already had, `upload` reads bytes we copied and may therefore
delete. `source_type` is a native ENUM on Postgres, so the value has to be added
to the type before a row can carry it.

Not reversible. Postgres cannot drop a value from an ENUM; undoing this means
recreating the type, which would need every `scans` row to be rewritten, and any
row already holding 'upload' would have nowhere to go. The downgrade says so
rather than pretending.

Revision ID: c9d4e1b70f52
Revises: a1c7f3e28d40
Create Date: 2026-09-04 15:02:18.664213

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c9d4e1b70f52'
down_revision: Union[str, Sequence[str], None] = 'a1c7f3e28d40'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    if op.get_bind().dialect.name != 'postgresql':
        # SQLite stores the enum as TEXT with a CHECK constraint that the test
        # suite's create_all writes from the current Python enum, so there is
        # nothing to alter there.
        return
    # ALTER TYPE ... ADD VALUE cannot run inside a transaction block before
    # PG 12; the autocommit block is explicit so this works on any of them.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE source_type ADD VALUE IF NOT EXISTS 'upload'")


def downgrade() -> None:
    """Downgrade schema."""
    raise NotImplementedError(
        "Postgres cannot remove a value from an ENUM. Downgrading past this "
        "revision means recreating the source_type type, and any scans row "
        "holding 'upload' would have no value left to hold."
    )
