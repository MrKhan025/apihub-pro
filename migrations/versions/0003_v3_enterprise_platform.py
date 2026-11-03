"""0003_v3_enterprise_platform: Upgrade schema for v3.0 AI Gateway, Monetization, Resilience, Security & DDD Event Sourcing.

Revision ID: 0003_v3_enterprise_platform
Revises: 0002_v2_advanced_engine
Create Date: 2026-11-03 14:45:00
"""

revision = "0003_v3_enterprise_platform"
down_revision = "0002_v2_advanced_engine"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Apply v3.0 enterprise tables (AI Gateway, Stripe Billing, Canary, Circuit Breakers, Service Discovery, Replay Vault, Threat Intel, JWKS, Event Sourcing)."""
    from apihub.database import db

    db.init_db()


def downgrade() -> None:
    """Downgrade to 0002_v2_advanced_engine."""
    from apihub.database import db

    db.run_migrations("0002_v2_advanced_engine")
