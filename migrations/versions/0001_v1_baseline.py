"""0001_v1_baseline: Initial API-Hub v1 baseline schema.

Revision ID: 0001_v1_baseline
Revises: None
Create Date: 2026-10-01 00:00:00
"""

revision = "0001_v1_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial v1 baseline tables (users, projects, api_keys, dynamic_endpoints)."""
    from apihub.database import db

    db.run_migrations("0001_v1_baseline")


def downgrade() -> None:
    """Downgrade v1 baseline tables."""
    pass
