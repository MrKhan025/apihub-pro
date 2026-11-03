"""
Idempotent workspace seed generator for API-Hub-Pro (apihub-pro).
Creates sample users, projects, dynamic v1/v2 endpoints, API keys, webhooks,
marketplace listings, and initial operational analytics when requested.
"""

from __future__ import annotations

import secrets
from typing import Any, Dict

from apihub.analytics import analytics_engine
from apihub.database import db
from apihub.gateway import gateway_manager
from apihub.marketplace import marketplace_manager
from apihub.security import security_manager
from apihub.webhooks import webhook_manager


def seed_demo_workspace() -> Dict[str, Any]:
    """Ensure a rich demo workspace exists for interactive dashboard exploration."""
    existing_admin = db.fetch_one("SELECT * FROM users WHERE username = 'admin'")
    if existing_admin:
        proj = db.fetch_one("SELECT * FROM projects ORDER BY created_at ASC LIMIT 1")
        return {
            "seeded": False,
            "message": "Workspace already seeded",
            "admin_user_id": existing_admin["id"],
            "default_project_id": proj["id"] if proj else None,
        }

    # Use ephemeral runtime password so no static credential is ever hardcoded
    runtime_demo_pw = f"Demo#{secrets.token_hex(6)}"
    admin = security_manager.create_user(
        username="admin",
        email="admin@apihub-pro.local",
        password=runtime_demo_pw,
        role="admin",
    )
    mfa_info = security_manager.setup_mfa(admin["id"])
    security_manager.enable_mfa(admin["id"], mfa_info["current_code_preview"])
    dev = security_manager.create_user(
        username="dev_lead",
        email="dev@apihub-pro.local",
        password=runtime_demo_pw,
        role="developer",
    )

    project = marketplace_manager.create_project(
        name="Core FinTech Gateway",
        owner_id=admin["id"],
        description="Production API Gateway for currency rates, customer profiles, and order webhooks",
        plan_tier="pro",
        slug="core-fintech-gateway",
    )
    marketplace_manager.add_project_member(
        project_id=project["id"],
        user_id=dev["id"],
        permission="editor",
        actor_id=admin["id"],
    )

    api_key_info = security_manager.create_api_key(
        project_id=project["id"],
        user_id=admin["id"],
        name="Default Dashboard Explorer Key",
        scopes=["gateway:invoke", "analytics:read", "endpoints:write"],
        rate_limit_rpm=120,
        ttl_days=90,
    )

    ep1 = gateway_manager.register_endpoint(
        project_id=project["id"],
        name="Exchange Rates Feed",
        version="v1",
        path="/fx/rates",
        method="GET",
        lifecycle_state="deprecated",
        deprecation_date="2026-10-15",
        sunset_date="2027-01-01",
        timeout_ms=3000,
        cache_ttl_seconds=30,
        auth_required=False,
        rate_limit_rpm=120,
        response_mode="mock",
        mock_status_code=200,
        mock_response_body={"base": "USD", "rates": {"INR": 84.15, "EUR": 0.92, "GBP": 0.78}},
        response_transform={"wrap_envelope": True, "envelope_key": "fx_data"},
        description="Legacy v1 exchange rate endpoint (deprecated in favor of v2)",
        tags=["fintech", "fx", "v1"],
        actor_id=admin["id"],
    )

    ep2 = gateway_manager.register_endpoint(
        project_id=project["id"],
        name="Real-Time FX Quotes v2",
        version="v2",
        path="/fx/quotes",
        method="GET",
        lifecycle_state="active",
        timeout_ms=2500,
        cache_ttl_seconds=60,
        auth_required=False,
        rate_limit_rpm=300,
        response_mode="mock",
        mock_status_code=200,
        mock_response_body={
            "pair": "USD/INR",
            "spot": 84.18,
            "spread_bps": 1.4,
            "account_number": "998877665544",
        },
        response_transform={
            "mask_fields": ["account_number"],
            "add_headers": {"X-FX-Engine": "APIHub-Pro-v2"},
            "wrap_envelope": True,
        },
        description="High-speed v2 FX quote feed with PII masking and Redis caching",
        tags=["fintech", "fx", "v2"],
        actor_id=admin["id"],
    )

    ep3 = gateway_manager.register_endpoint(
        project_id=project["id"],
        name="Order Payment Echo Transform",
        version="v2",
        path="/orders/charge",
        method="POST",
        lifecycle_state="active",
        timeout_ms=4000,
        auth_required=True,
        rate_limit_rpm=60,
        response_mode="echo",
        request_transform={
            "add_headers": {"X-Gateway-Verified": "true"},
            "rename_body_fields": {"amt": "amount_usd"},
            "inject_body_fields": {"currency": "USD"},
        },
        response_transform={"wrap_envelope": True},
        description="Transforms incoming payment payloads and echoes normalized request",
        tags=["orders", "payments"],
        actor_id=admin["id"],
    )

    wh = webhook_manager.register_webhook(
        project_id=project["id"],
        name="Order Settlement Webhook",
        target_url="https://hooks.apihub-pro.internal/orders/settled",
        events=["endpoint.invoked", "security.alert", "key.rotated"],
        max_retries=3,
        backoff_strategy="exponential",
        initial_delay_ms=150,
        actor_id=admin["id"],
    )
    webhook_manager.dispatch_event(
        webhook_id=wh["id"],
        event_type="endpoint.invoked",
        data={"endpoint": "/gateway/v2/fx/quotes", "status": 200},
    )

    marketplace_manager.publish_marketplace_listing(
        project_id=project["id"],
        title="Global FX & Crypto Spot Feed API",
        summary="Low-latency institutional foreign exchange and crypto spot rates with automatic Redis caching.",
        sample_endpoint_path="/gateway/v2/fx/quotes",
        category="finance",
        version="v2",
        pricing_plan_required="free",
        price_monthly_usd=0.0,
        rate_limit_rpm=300,
        actor_id=admin["id"],
    )
    marketplace_manager.publish_marketplace_listing(
        project_id=project["id"],
        title="Zero-Trust Identity & Fraud Scoring API",
        summary="Real-time IP reputation, velocity throttling, and device risk telemetry for checkout flows.",
        sample_endpoint_path="/gateway/v2/orders/charge",
        category="security",
        version="v2",
        pricing_plan_required="pro",
        price_monthly_usd=49.0,
        rate_limit_rpm=600,
        actor_id=admin["id"],
    )

    # Record sample analytics metrics across percentiles
    sample_latencies = [8.4, 11.2, 14.5, 18.0, 22.1, 29.5, 41.0, 68.4, 112.0, 4.9]
    for idx, lat in enumerate(sample_latencies):
        analytics_engine.record_request(
            project_id=project["id"],
            endpoint_id=ep2["id"] if idx % 2 == 0 else ep1["id"],
            api_key_id=api_key_info["id"],
            version="v2" if idx % 2 == 0 else "v1",
            method="GET",
            path="/fx/quotes" if idx % 2 == 0 else "/fx/rates",
            status_code=200 if idx < 9 else 429,
            latency_ms=lat,
            cache_hit=(idx % 3 == 0),
        )

    return {
        "seeded": True,
        "admin_user": admin,
        "developer_user": dev,
        "project": project,
        "default_api_key": api_key_info["api_key"],
        "endpoints": [ep1["id"], ep2["id"], ep3["id"]],
    }
