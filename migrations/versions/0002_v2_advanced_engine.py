"""0002_v2_advanced_engine: Upgrade schema for API-Hub-Pro v2.0 Advanced API Engine.

Revision ID: 0002_v2_advanced_engine
Revises: 0001_v1_baseline
Create Date: 2026-11-03 00:00:00
"""

revision = "0002_v2_advanced_engine"
down_revision = "0001_v1_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Upgrade to v2.0 schema:
    - RBAC & project_members
    - API key expiration & grace-period rotation
    - Dynamic endpoint versioning, lifecycle states, and request/response transforms
    - Webhooks & webhook_deliveries with retry policies
    - Tamper-evident hash-chained audit_logs
    - High-resolution request_metrics for percentile analytics
    - Marketplace listings & subscription plans
    """
    from apihub.database import db

    db.run_migrations("0002_v2_advanced_engine")


def downgrade() -> None:
    """Downgrade to 0001_v1_baseline."""
    from apihub.database import db

    db.run_migrations("0001_v1_baseline")
