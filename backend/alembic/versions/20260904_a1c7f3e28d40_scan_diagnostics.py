"""scans.diagnostics

Per-collector and per-extension reporting for a run (SPEC.md §2's partial
results). Nullable, because every scan that ran before this migration has no
diagnostics to record and inventing an empty object for them would claim the
collectors were all checked and all silent.

Revision ID: a1c7f3e28d40
Revises: 51ab36a72007
Create Date: 2026-09-04 10:12:44.180231

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a1c7f3e28d40'
down_revision: Union[str, Sequence[str], None] = '51ab36a72007'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'scans',
        sa.Column(
            'diagnostics',
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scans', 'diagnostics')
