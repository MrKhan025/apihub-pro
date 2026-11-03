"""
Multi-Project Workspace, API Marketplace & Subscription Plans Engine for API-Hub-Pro (apihub-pro).
Provides:
- Tiered Subscription Plans (`free`, `pro`, `enterprise`) with RPM & daily quotas
- Multi-Project creation & RBAC project member assignment (`owner`, `editor`, `reader`)
- API Marketplace catalog publishing, discovery, and instant project subscriptions
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional

from apihub.database import db
from apihub.security import AuditLogger, PROJECT_PERMISSION_LEVELS


SUBSCRIPTION_PLANS: Dict[str, Dict[str, Any]] = {
    "free": {
        "id": "free",
        "name": "Free Developer",
        "price_monthly_usd": 0.0,
        "rpm_limit": 60,
        "daily_quota": 10_000,
        "max_projects": 3,
        "max_endpoints_per_project": 10,
        "features": [
            "Dynamic API creation",
            "Redis rate limiting (60 RPM)",
            "Basic analytics",
            "Community marketplace access",
        ],
    },
    "pro": {
        "id": "pro",
        "name": "Pro Growth",
        "price_monthly_usd": 49.0,
        "rpm_limit": 600,
        "daily_quota": 250_000,
        "max_projects": 20,
        "max_endpoints_per_project": 100,
        "features": [
            "Request & response transformation pipeline",
            "Grace-period API key rotation",
            "Webhooks with exponential backoff retries",
            "Latency percentiles (p50/p90/p95/p99) & CSV exports",
        ],
    },
    "enterprise": {
        "id": "enterprise",
        "name": "Enterprise Zero-Trust",
        "price_monthly_usd": 249.0,
        "rpm_limit": 5000,
        "daily_quota": 5_000_000,
        "max_projects": 500,
        "max_endpoints_per_project": 2000,
        "features": [
            "Dedicated Redis & PostgreSQL pool priority",
            "RFC 6238 TOTP MFA & RBAC project isolation",
            "HMAC-SHA256 tamper-evident audit chain",
            "Automated security auditing & premium marketplace APIs",
        ],
    },
}


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or f"item-{uuid.uuid4().hex[:6]}"


class ProjectAndMarketplaceManager:
    """Manages projects, project member permissions, subscription plans, and marketplace listings."""

    @staticmethod
    def list_plans() -> List[Dict[str, Any]]:
        return list(SUBSCRIPTION_PLANS.values())

    @classmethod
    def create_project(
        cls,
        name: str,
        owner_id: str,
        description: str = "",
        plan_tier: str = "free",
        slug: Optional[str] = None,
    ) -> Dict[str, Any]:
        if plan_tier not in SUBSCRIPTION_PLANS:
            raise ValueError(f"Invalid plan_tier '{plan_tier}'")
        plan = SUBSCRIPTION_PLANS[plan_tier]
        proj_id = f"prj_{uuid.uuid4().hex[:12]}"
        proj_slug = slug or _slugify(name)
        existing = db.fetch_one("SELECT id FROM projects WHERE slug = ?", (proj_slug,))
        if existing:
            proj_slug = f"{proj_slug}-{uuid.uuid4().hex[:4]}"
        now = time.time()

        db.execute(
            """
            INSERT INTO projects
            (id, name, slug, description, owner_id, plan_tier, rpm_limit, daily_quota, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                proj_id,
                name.strip(),
                proj_slug,
                description,
                owner_id,
                plan_tier,
                int(plan["rpm_limit"]),
                int(plan["daily_quota"]),
                now,
                now,
            ),
        )
        member_id = f"pm_{uuid.uuid4().hex[:12]}"
        db.execute(
            """
            INSERT INTO project_members (id, project_id, user_id, permission, created_at)
            VALUES (?, ?, ?, 'owner', ?)
            """,
            (member_id, proj_id, owner_id, now),
        )
        AuditLogger.log_event(
            event_type="project.created",
            description=f"Created project '{name}' ({proj_slug}) on plan '{plan_tier}'",
            actor_id=owner_id,
            project_id=proj_id,
        )
        return cls.get_project(proj_id)  # type: ignore

    @staticmethod
    def get_project(project_id: str) -> Optional[Dict[str, Any]]:
        row = db.fetch_one("SELECT * FROM projects WHERE id = ?", (project_id,))
        if not row:
            return None
        members = db.fetch_all(
            """
            SELECT pm.user_id, pm.permission, pm.created_at, u.username, u.email, u.role
            FROM project_members pm
            LEFT JOIN users u ON u.id = pm.user_id
            WHERE pm.project_id = ?
            """,
            (project_id,),
        )
        return {
            **dict(row),
            "is_active": bool(row["is_active"]),
            "members": [dict(m) for m in members],
        }

    @classmethod
    def list_projects(cls, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if not user_id:
            rows = db.fetch_all("SELECT id FROM projects ORDER BY created_at DESC")
        else:
            user = db.fetch_one("SELECT role FROM users WHERE id = ?", (user_id,))
            if user and user["role"] == "admin":
                rows = db.fetch_all("SELECT id FROM projects ORDER BY created_at DESC")
            else:
                rows = db.fetch_all(
                    """
                    SELECT DISTINCT p.id, p.created_at FROM projects p
                    LEFT JOIN project_members pm ON pm.project_id = p.id
                    WHERE p.owner_id = ? OR pm.user_id = ?
                    ORDER BY p.created_at DESC
                    """,
                    (user_id, user_id),
                )
        return [cls.get_project(r["id"]) for r in rows if r]  # type: ignore

    @staticmethod
    def add_project_member(
        project_id: str,
        user_id: str,
        permission: str = "editor",
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if permission not in PROJECT_PERMISSION_LEVELS:
            raise ValueError(f"Invalid permission '{permission}'. Use owner, editor, or reader.")
        now = time.time()
        pm_id = f"pm_{uuid.uuid4().hex[:12]}"
        db.execute(
            """
            INSERT INTO project_members (id, project_id, user_id, permission, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(project_id, user_id) DO UPDATE SET permission = excluded.permission
            """,
            (pm_id, project_id, user_id, permission, now),
        )
        AuditLogger.log_event(
            event_type="project.member_updated",
            description=f"Granted '{permission}' access on project {project_id} to user {user_id}",
            actor_id=actor_id,
            project_id=project_id,
        )
        return {
            "project_id": project_id,
            "user_id": user_id,
            "permission": permission,
            "updated_at": now,
        }

    @classmethod
    def publish_marketplace_listing(
        cls,
        project_id: str,
        title: str,
        summary: str,
        sample_endpoint_path: str,
        category: str = "data",
        version: str = "v1",
        pricing_plan_required: str = "free",
        price_monthly_usd: float = 0.0,
        rate_limit_rpm: int = 60,
        documentation_md: str = "",
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if pricing_plan_required not in SUBSCRIPTION_PLANS:
            raise ValueError(f"Invalid pricing_plan_required '{pricing_plan_required}'")
        listing_id = f"mkt_{uuid.uuid4().hex[:12]}"
        slug = f"{_slugify(title)}-{uuid.uuid4().hex[:4]}"
        now = time.time()

        db.execute(
            """
            INSERT INTO marketplace_listings (
                id, project_id, title, slug, category, summary, version,
                pricing_plan_required, price_monthly_usd, rate_limit_rpm,
                documentation_md, sample_endpoint_path, is_verified, subscribers_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)
            """,
            (
                listing_id,
                project_id,
                title.strip(),
                slug,
                category.strip().lower(),
                summary.strip(),
                version.strip(),
                pricing_plan_required,
                float(price_monthly_usd),
                int(rate_limit_rpm),
                documentation_md,
                sample_endpoint_path,
                now,
            ),
        )
        AuditLogger.log_event(
            event_type="marketplace.published",
            description=f"Published marketplace API '{title}' ({slug})",
            actor_id=actor_id,
            project_id=project_id,
        )
        row = db.fetch_one("SELECT * FROM marketplace_listings WHERE id = ?", (listing_id,))
        return dict(row) if row else {}

    @staticmethod
    def list_marketplace_listings(category: Optional[str] = None) -> List[Dict[str, Any]]:
        if category:
            rows = db.fetch_all(
                "SELECT * FROM marketplace_listings WHERE category = ? ORDER BY subscribers_count DESC, created_at DESC",
                (category.lower(),),
            )
        else:
            rows = db.fetch_all(
                "SELECT * FROM marketplace_listings ORDER BY subscribers_count DESC, created_at DESC"
            )
        return [dict(r) for r in rows]

    @classmethod
    def subscribe_project(
        cls,
        project_id: str,
        user_id: str,
        plan_id: str = "pro",
        listing_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if plan_id not in SUBSCRIPTION_PLANS:
            raise ValueError(f"Unsupported subscription plan '{plan_id}'")
        plan = SUBSCRIPTION_PLANS[plan_id]
        now = time.time()
        sub_id = f"sub_{uuid.uuid4().hex[:12]}"

        db.execute(
            """
            INSERT INTO subscriptions
            (id, project_id, user_id, plan_id, listing_id, status, rpm_quota, daily_quota, started_at, expires_at)
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
            """,
            (
                sub_id,
                project_id,
                user_id,
                plan_id,
                listing_id,
                int(plan["rpm_limit"]),
                int(plan["daily_quota"]),
                now,
                now + 30 * 86400,
            ),
        )
        db.execute(
            """
            UPDATE projects SET plan_tier = ?, rpm_limit = ?, daily_quota = ?, updated_at = ?
            WHERE id = ?
            """,
            (plan_id, int(plan["rpm_limit"]), int(plan["daily_quota"]), now, project_id),
        )
        if listing_id:
            db.execute(
                "UPDATE marketplace_listings SET subscribers_count = subscribers_count + 1 WHERE id = ?",
                (listing_id,),
            )
        AuditLogger.log_event(
            event_type="marketplace.subscribed",
            description=f"Subscribed project {project_id} to plan '{plan_id}'"
            + (f" and listing {listing_id}" if listing_id else ""),
            actor_id=user_id,
            project_id=project_id,
            metadata={"subscription_id": sub_id, "plan_id": plan_id, "listing_id": listing_id},
        )
        return {
            "subscription_id": sub_id,
            "project_id": project_id,
            "user_id": user_id,
            "plan": plan,
            "listing_id": listing_id,
            "status": "active",
            "started_at": now,
        }


marketplace_manager = ProjectAndMarketplaceManager()
