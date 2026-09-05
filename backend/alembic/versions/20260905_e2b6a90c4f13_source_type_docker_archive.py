"""source_type: docker_archive

A `docker save` tar the browser sent us is its own source type, not a
`docker_image` whose ref happens to name a file. The difference is the same one
`upload` draws against `folder`: `docker_image` asks a local daemon for the tar,
`docker_archive` reads bytes we copied and may therefore delete. `source_type`
is a native ENUM on Postgres, so the value has to be added to the type before a
row can carry it.

Not reversible, for the reason the `upload` revision gives: Postgres cannot drop
a value from an ENUM.

Revision ID: e2b6a90c4f13
Revises: c9d4e1b70f52
Create Date: 2026-09-05 11:18:44.201377

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e2b6a90c4f13'
down_revision: Union[str, Sequence[str], None] = 'c9d4e1b70f52'
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
        op.execute("ALTER TYPE source_type ADD VALUE IF NOT EXISTS 'docker_archive'")


def downgrade() -> None:
    """Downgrade schema."""
    raise NotImplementedError(
        "Postgres cannot remove a value from an ENUM. Downgrading past this "
        "revision means recreating the source_type type, and any scans row "
        "holding 'docker_archive' would have no value left to hold."
    )
