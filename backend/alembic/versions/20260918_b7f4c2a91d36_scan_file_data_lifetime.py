"""scan_files.data_lifetime_years

Per-asset X for Mosca's inequality (SPEC.md §12). `scans.data_lifetime_years` is
one number for a whole estate, which scores a customer database and a monitoring
endpoint identically. This column carries the lifetime the user set for one file
on the approval screen, where they are already looking at the tree and deciding
what may be read.

Nullable, and null is the ordinary case: it means "no override", so the file is
scored at the scan-wide value. Nothing backfills — a scan created before this
column existed had one lifetime for everything, and still does.

Revision ID: b7f4c2a91d36
Revises: e2b6a90c4f13
Create Date: 2026-09-18 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b7f4c2a91d36'
down_revision: Union[str, Sequence[str], None] = 'e2b6a90c4f13'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'scan_files',
        sa.Column('data_lifetime_years', sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scan_files', 'data_lifetime_years')
