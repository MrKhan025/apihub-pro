"""
FastAPI Application & REST Controller for API-Hub-Pro (apihub-pro) v2.0.
Maintains 100% backward compatibility with v1 endpoints while exposing the complete
v2.0 Advanced API Engine:
- Dynamic API Gateway Registration, Versioning, Lifecycle, Transformations & Timeouts
- Redis-backed Distributed Rate Limiting & Response Caching
- RBAC, Project-Level Permissions, API Key Expiration & Grace-Period Rotation
- Login Throttling, RFC 6238 TOTP MFA, Password Reset & Request Abuse Prevention
- Tamper-evident Hash-Chained Audit Trail & Automated Security Auditing
- Live Operational Analytics (RPM, Daily Usage, Latency Percentiles, SVG Charts, CSV/JSON Export)
- API Marketplace & Tiered Subscription Plans
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from apihub import __app_name__, __version__
from apihub.analytics import analytics_engine
from apihub.config import settings
from apihub.database import MIGRATION_REVISIONS, db
from apihub.gateway import gateway_manager
from apihub.marketplace import marketplace_manager
from apihub.rate_limiter import redis_store, response_cache
from apihub.security import (
    AuditLogger,
    ROLE_PERMISSIONS,
    security_manager,
    verify_session_token,
)
from apihub.webhooks import webhook_manager


WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(
    title="API-Hub-Pro (apihub-pro) — Enterprise API Gateway & Management Engine",
    version=__version__,
    description=(
        "Dynamic API Gateway, Redis Distributed Rate Limiting, Multi-Project RBAC, "
        "MFA, Webhook Retries, Live Percentile Analytics, and API Marketplace."
    ),
)

if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


# ---------------------------------------------------------------------------
# Pure ASGI Request Size Limits & Abuse Prevention Middleware (Non-blocking)
# ---------------------------------------------------------------------------
class SecurityAndAbuseMiddleware:
    """Pure ASGI middleware that inspects request size and SQLi/XSS/Path Traversal payloads."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        chunks: List[bytes] = []
        more_body = True
        while more_body:
            msg = await receive()
            if msg.get("type") == "http.request":
                chunks.append(msg.get("body", b""))
                more_body = bool(msg.get("more_body", False))
            else:
                more_body = False

        raw_body = b"".join(chunks)
        path = scope.get("path", "")
        query_string = (scope.get("query_string") or b"").decode("utf-8", errors="ignore")

        abuse = security_manager.inspect_request_abuse(
            raw_body=raw_body,
            path=path,
            query_string=query_string,
        )
        if abuse and abuse.get("blocked"):
            client_info = scope.get("client")
            client_ip = client_info[0] if client_info else "127.0.0.1"
            AuditLogger.log_event(
                event_type="security.request_blocked",
                severity="high",
                description=abuse["message"],
                actor_ip=client_ip,
                metadata={"path": path, "reason": abuse["reason"]},
            )
            res = JSONResponse(
                status_code=int(abuse["status_code"]),
                content={"error": abuse["reason"], "detail": abuse["message"]},
                headers={
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "SAMEORIGIN",
                    "X-APIHub-Version": __version__,
                },
            )
            await res(scope, receive, send)
            return

        body_sent = False

        async def replay_receive() -> Dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return {"type": "http.disconnect"}

        from apihub.observability import trace_collector
        req_headers_dict = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in (scope.get("headers") or [])
        }
        trace_ctx = trace_collector.parse_or_create_traceparent(req_headers_dict.get("traceparent"))
        start_perf = time.perf_counter()
        captured_status = 200

        async def send_with_security_headers(message: Dict[str, Any]) -> None:
            nonlocal captured_status
            if message.get("type") == "http.response.start":
                captured_status = int(message.get("status", 200))
                raw_headers = list(message.get("headers", []))
                raw_headers.append((b"x-content-type-options", b"nosniff"))
                raw_headers.append((b"x-frame-options", b"SAMEORIGIN"))
                raw_headers.append((b"x-apihub-version", __version__.encode("utf-8")))
                raw_headers.append((b"traceparent", trace_ctx["traceparent"].encode("utf-8")))
                raw_headers.append((b"x-trace-id", trace_ctx["trace_id"].encode("utf-8")))
                message["headers"] = raw_headers
            await send(message)

        await self.app(scope, replay_receive, send_with_security_headers)
        dur_ms = (time.perf_counter() - start_perf) * 1000.0
        trace_collector.record_trace(
            trace_ctx=trace_ctx,
            method=scope.get("method", "GET"),
            path=path,
            status_code=captured_status,
            duration_ms=dur_ms,
        )


app.add_middleware(SecurityAndAbuseMiddleware)


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------
class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    email: str = Field(..., min_length=5, max_length=120)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="developer")


class UserLoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None


class MFASetupRequest(BaseModel):
    user_id: str


class MFAVerifyRequest(BaseModel):
    user_id: str
    code: str


class PasswordResetRequestModel(BaseModel):
    email_or_username: str


class PasswordResetConfirmModel(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class ProjectCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    owner_id: str
    description: str = ""
    plan_tier: str = "free"
    slug: Optional[str] = None


class ProjectMemberRequest(BaseModel):
    user_id: str
    permission: str = "editor"
    actor_id: Optional[str] = None


class APIKeyCreateRequest(BaseModel):
    project_id: str
    user_id: str
    name: str = Field(..., min_length=2, max_length=100)
    scopes: Optional[List[str]] = None
    rate_limit_rpm: int = 60
    ttl_days: Optional[int] = 90


class APIKeyRotateRequest(BaseModel):
    actor_id: str = "system"
    grace_period_seconds: int = 86400
    ttl_days: int = 90


class DynamicEndpointCreateRequest(BaseModel):
    project_id: str
    name: str = Field(..., min_length=2, max_length=120)
    path: str = Field(..., min_length=1, max_length=255)
    method: str = "GET"
    version: str = "v1"
    lifecycle_state: str = "active"
    deprecation_date: Optional[str] = None
    sunset_date: Optional[str] = None
    timeout_ms: int = 5000
    cache_ttl_seconds: int = 0
    auth_required: bool = False
    rate_limit_rpm: int = 60
    response_mode: str = "mock"
    upstream_url: Optional[str] = None
    mock_status_code: int = 200
    mock_response_body: Dict[str, Any] = Field(default_factory=lambda: {"status": "ok"})
    mock_headers: Dict[str, str] = Field(default_factory=dict)
    simulated_latency_ms: int = 0
    request_transform: Dict[str, Any] = Field(default_factory=dict)
    response_transform: Dict[str, Any] = Field(default_factory=dict)
    description: str = ""
    tags: List[str] = Field(default_factory=list)
    actor_id: Optional[str] = None


class DynamicEndpointUpdateRequest(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    path: Optional[str] = None
    method: Optional[str] = None
    lifecycle_state: Optional[str] = None
    deprecation_date: Optional[str] = None
    sunset_date: Optional[str] = None
    timeout_ms: Optional[int] = None
    cache_ttl_seconds: Optional[int] = None
    auth_required: Optional[bool] = None
    rate_limit_rpm: Optional[int] = None
    response_mode: Optional[str] = None
    mock_status_code: Optional[int] = None
    mock_response_body: Optional[Dict[str, Any]] = None
    mock_headers: Optional[Dict[str, str]] = None
    simulated_latency_ms: Optional[int] = None
    request_transform: Optional[Dict[str, Any]] = None
    response_transform: Optional[Dict[str, Any]] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    actor_id: Optional[str] = None


class WebhookCreateRequest(BaseModel):
    project_id: str
    name: str
    target_url: str
    events: Optional[List[str]] = None
    secret: Optional[str] = None
    max_retries: int = 3
    backoff_strategy: str = "exponential"
    initial_delay_ms: int = 200
    timeout_ms: int = 3000
    actor_id: Optional[str] = None


class WebhookTriggerRequest(BaseModel):
    event_type: str = "endpoint.invoked"
    data: Dict[str, Any] = Field(default_factory=dict)
    simulate_failures_before_success: int = 0


class MarketplaceListingRequest(BaseModel):
    project_id: str
    title: str
    summary: str
    sample_endpoint_path: str
    category: str = "data"
    version: str = "v1"
    pricing_plan_required: str = "free"
    price_monthly_usd: float = 0.0
    rate_limit_rpm: int = 60
    documentation_md: str = ""
    actor_id: Optional[str] = None


class SubscriptionCreateRequest(BaseModel):
    project_id: str
    user_id: str
    plan_id: str = "pro"
    listing_id: Optional[str] = None


# ---------------------------------------------------------------------------
# UI Dashboard Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def serve_dashboard() -> Response:
    index_file = WEB_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file), media_type="text/html")
    return HTMLResponse("<h1>API-Hub-Pro v2.0 Gateway Active</h1>")


# ---------------------------------------------------------------------------
# Health & Backward-Compatible v1 Endpoints
# ---------------------------------------------------------------------------
@app.get("/health", tags=["v1-compat", "infrastructure"])
def health_check() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": __app_name__,
        "version": __version__,
        "database_revision": db.get_current_revision(),
        "redis_backend": redis_store.backend_mode,
        "timestamp": time.time(),
    }


@app.get("/api/v1/status", tags=["v1-compat"])
def legacy_v1_status() -> Dict[str, Any]:
    """Backward-compatible v1 status endpoint preserved for existing integrations."""
    return {
        "status": "ok",
        "api_version": "v1",
        "engine_version": __version__,
        "backward_compatible": True,
        "features": ["gateway", "rate_limiting", "rbac", "analytics", "marketplace"],
    }


@app.get("/api/v1/endpoints", tags=["v1-compat"])
def legacy_v1_list_endpoints(project_id: Optional[str] = None) -> Dict[str, Any]:
    """Backward-compatible v1 endpoint listing."""
    endpoints = gateway_manager.list_endpoints(project_id=project_id)
    return {"status": "ok", "count": len(endpoints), "endpoints": endpoints}


@app.get("/api/v1/projects", tags=["v1-compat"])
def legacy_v1_list_projects() -> Dict[str, Any]:
    """Backward-compatible v1 project listing."""
    projects = marketplace_manager.list_projects()
    return {"status": "ok", "count": len(projects), "projects": projects}


@app.get("/api/v1/keys", tags=["v1-compat"])
def legacy_v1_list_keys(project_id: Optional[str] = None) -> Dict[str, Any]:
    """Backward-compatible v1 API key metadata listing (never exposes raw key hashes)."""
    if project_id:
        rows = db.fetch_all(
            "SELECT id, project_id, user_id, name, key_prefix, scopes, rate_limit_rpm, status, expires_at, created_at FROM api_keys WHERE project_id = ?",
            (project_id,),
        )
    else:
        rows = db.fetch_all(
            "SELECT id, project_id, user_id, name, key_prefix, scopes, rate_limit_rpm, status, expires_at, created_at FROM api_keys"
        )
    return {"status": "ok", "count": len(rows), "keys": rows}


# ---------------------------------------------------------------------------
# v2 Authentication, RBAC, MFA & Password Reset Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/v2/auth/register", status_code=201, tags=["security-auth"])
def register_user(req: UserRegisterRequest) -> Dict[str, Any]:
    try:
        user = security_manager.create_user(
            username=req.username,
            email=req.email,
            password=req.password,
            role=req.role,
        )
        return {"status": "created", "user": user}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v2/auth/login", tags=["security-auth"])
def login_user(req: UserLoginRequest, request: Request) -> Response:
    client_ip = request.client.host if request.client else "127.0.0.1"
    ok, status_code, payload = security_manager.authenticate_user(
        username=req.username,
        password=req.password,
        totp_code=req.totp_code,
        client_ip=client_ip,
    )
    return JSONResponse(status_code=status_code, content=payload)


@app.post("/api/v2/auth/mfa/setup", tags=["security-auth"])
def setup_mfa(req: MFASetupRequest) -> Dict[str, Any]:
    try:
        return security_manager.setup_mfa(req.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/v2/auth/mfa/verify", tags=["security-auth"])
def verify_and_enable_mfa(req: MFAVerifyRequest) -> Dict[str, Any]:
    ok = security_manager.enable_mfa(req.user_id, req.code)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid TOTP code or MFA not provisioned")
    return {"status": "mfa_enabled", "user_id": req.user_id}


@app.post("/api/v2/auth/password-reset/request", tags=["security-auth"])
def request_password_reset(req: PasswordResetRequestModel) -> Dict[str, Any]:
    token = security_manager.request_password_reset(req.email_or_username)
    return {
        "status": "reset_initiated",
        "message": "If the account exists, a time-bound single-use reset token has been issued.",
        "reset_token": token,
    }


@app.post("/api/v2/auth/password-reset/confirm", tags=["security-auth"])
def confirm_password_reset(req: PasswordResetConfirmModel) -> Dict[str, Any]:
    ok = security_manager.confirm_password_reset(req.token, req.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid, expired, or already-used reset token")
    return {"status": "password_updated"}


@app.get("/api/v2/users", tags=["security-auth"])
def list_users() -> Dict[str, Any]:
    rows = db.fetch_all(
        "SELECT id, username, email, role, mfa_enabled, is_active, failed_login_attempts, created_at FROM users ORDER BY created_at DESC"
    )
    users = [
        {
            **dict(r),
            "mfa_enabled": bool(r["mfa_enabled"]),
            "is_active": bool(r["is_active"]),
            "permissions": ROLE_PERMISSIONS.get(r["role"], []),
        }
        for r in rows
    ]
    return {"count": len(users), "users": users}


# ---------------------------------------------------------------------------
# v2 Multi-Project & RBAC Member Management
# ---------------------------------------------------------------------------
@app.post("/api/v2/projects", status_code=201, tags=["projects-rbac"])
def create_project(req: ProjectCreateRequest) -> Dict[str, Any]:
    try:
        proj = marketplace_manager.create_project(
            name=req.name,
            owner_id=req.owner_id,
            description=req.description,
            plan_tier=req.plan_tier,
            slug=req.slug,
        )
        return {"status": "created", "project": proj}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v2/projects", tags=["projects-rbac"])
def list_projects(user_id: Optional[str] = None) -> Dict[str, Any]:
    projects = marketplace_manager.list_projects(user_id=user_id)
    return {"count": len(projects), "projects": projects}


@app.get("/api/v2/projects/{project_id}", tags=["projects-rbac"])
def get_project_details(project_id: str, user_id: Optional[str] = None) -> Dict[str, Any]:
    proj = marketplace_manager.get_project(project_id)
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    if user_id and not security_manager.check_project_access(user_id, project_id, "reader"):
        raise HTTPException(status_code=403, detail="Insufficient project-level permissions")
    return proj


@app.post("/api/v2/projects/{project_id}/members", tags=["projects-rbac"])
def assign_project_member(project_id: str, req: ProjectMemberRequest) -> Dict[str, Any]:
    proj = marketplace_manager.get_project(project_id)
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    if req.actor_id and not security_manager.check_project_access(req.actor_id, project_id, "owner"):
        raise HTTPException(
            status_code=403, detail="Only project owners or admins can modify project members"
        )
    try:
        member = marketplace_manager.add_project_member(
            project_id=project_id,
            user_id=req.user_id,
            permission=req.permission,
            actor_id=req.actor_id,
        )
        return {"status": "updated", "member": member}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# v2 API Key Issuance, Expiration & Grace-Period Rotation
# ---------------------------------------------------------------------------
@app.post("/api/v2/keys", status_code=201, tags=["api-keys"])
def create_api_key(req: APIKeyCreateRequest) -> Dict[str, Any]:
    proj = marketplace_manager.get_project(req.project_id)
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    key_info = security_manager.create_api_key(
        project_id=req.project_id,
        user_id=req.user_id,
        name=req.name,
        scopes=req.scopes,
        rate_limit_rpm=req.rate_limit_rpm,
        ttl_days=req.ttl_days,
    )
    return key_info


@app.get("/api/v2/keys", tags=["api-keys"])
def list_api_keys(project_id: Optional[str] = None) -> Dict[str, Any]:
    if project_id:
        rows = db.fetch_all(
            """
            SELECT id, project_id, user_id, name, key_prefix, scopes, rate_limit_rpm,
                   status, expires_at, rotated_from_id, grace_period_until, last_used_at, created_at
            FROM api_keys WHERE project_id = ? ORDER BY created_at DESC
            """,
            (project_id,),
        )
    else:
        rows = db.fetch_all(
            """
            SELECT id, project_id, user_id, name, key_prefix, scopes, rate_limit_rpm,
                   status, expires_at, rotated_from_id, grace_period_until, last_used_at, created_at
            FROM api_keys ORDER BY created_at DESC
            """
        )
    keys = [
        {**dict(r), "scopes": json.loads(r["scopes"] or "[]")}
        for r in rows
    ]
    return {"count": len(keys), "keys": keys}


@app.post("/api/v2/keys/{key_id}/rotate", tags=["api-keys"])
def rotate_api_key(key_id: str, req: APIKeyRotateRequest) -> Dict[str, Any]:
    try:
        return security_manager.rotate_api_key(
            key_id=key_id,
            actor_id=req.actor_id,
            grace_period_seconds=req.grace_period_seconds,
            ttl_days=req.ttl_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/v2/keys/{key_id}/revoke", tags=["api-keys"])
def revoke_api_key(key_id: str, actor_id: str = "system") -> Dict[str, Any]:
    existing = db.fetch_one("SELECT * FROM api_keys WHERE id = ?", (key_id,))
    if not existing:
        raise HTTPException(status_code=404, detail="API key not found")
    db.execute("UPDATE api_keys SET status = 'revoked' WHERE id = ?", (key_id,))
    AuditLogger.log_event(
        event_type="apikey.revoked",
        description=f"Revoked API key {key_id}",
        actor_id=actor_id,
        project_id=existing["project_id"],
    )
    return {"status": "revoked", "key_id": key_id}


# ---------------------------------------------------------------------------
# v2 Dynamic API Gateway Management (Registration, Versioning, Lifecycle)
# ---------------------------------------------------------------------------
@app.post("/api/v2/gateway/endpoints", status_code=201, tags=["gateway"])
def register_dynamic_endpoint(req: DynamicEndpointCreateRequest) -> Dict[str, Any]:
    if req.actor_id and not security_manager.check_project_access(
        req.actor_id, req.project_id, "editor"
    ):
        raise HTTPException(status_code=403, detail="Editor or Owner project permission required")
    try:
        ep = gateway_manager.register_endpoint(
            project_id=req.project_id,
            name=req.name,
            path=req.path,
            method=req.method,
            version=req.version,
            lifecycle_state=req.lifecycle_state,
            deprecation_date=req.deprecation_date,
            sunset_date=req.sunset_date,
            timeout_ms=req.timeout_ms,
            cache_ttl_seconds=req.cache_ttl_seconds,
            auth_required=req.auth_required,
            rate_limit_rpm=req.rate_limit_rpm,
            response_mode=req.response_mode,
            upstream_url=req.upstream_url,
            mock_status_code=req.mock_status_code,
            mock_response_body=req.mock_response_body,
            mock_headers=req.mock_headers,
            simulated_latency_ms=req.simulated_latency_ms,
            request_transform=req.request_transform,
            response_transform=req.response_transform,
            description=req.description,
            tags=req.tags,
            actor_id=req.actor_id,
        )
        return {"status": "registered", "endpoint": ep}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v2/gateway/endpoints", tags=["gateway"])
def list_dynamic_endpoints(
    project_id: Optional[str] = None,
    version: Optional[str] = None,
    lifecycle_state: Optional[str] = None,
) -> Dict[str, Any]:
    endpoints = gateway_manager.list_endpoints(
        project_id=project_id,
        version=version,
        lifecycle_state=lifecycle_state,
    )
    return {"count": len(endpoints), "endpoints": endpoints}


@app.get("/api/v2/gateway/endpoints/{endpoint_id}", tags=["gateway"])
def get_dynamic_endpoint(endpoint_id: str) -> Dict[str, Any]:
    ep = gateway_manager.get_endpoint(endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Dynamic endpoint not found")
    return ep


@app.put("/api/v2/gateway/endpoints/{endpoint_id}", tags=["gateway"])
def update_dynamic_endpoint(
    endpoint_id: str, req: DynamicEndpointUpdateRequest
) -> Dict[str, Any]:
    updates = {k: v for k, v in (req.model_dump() if hasattr(req, "model_dump") else req.dict()).items() if v is not None and k != "actor_id"}
    try:
        ep = gateway_manager.update_endpoint(endpoint_id, updates, actor_id=req.actor_id)
        return {"status": "updated", "endpoint": ep}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/v2/gateway/endpoints/{endpoint_id}", tags=["gateway"])
def delete_dynamic_endpoint(
    endpoint_id: str, actor_id: Optional[str] = None
) -> Dict[str, Any]:
    ok = gateway_manager.delete_endpoint(endpoint_id, actor_id=actor_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Dynamic endpoint not found")
    return {"status": "deleted", "endpoint_id": endpoint_id}


# ---------------------------------------------------------------------------
# Dynamic Gateway Runtime Dispatcher (`/gateway/{version}/{endpoint_path:path}`)
# ---------------------------------------------------------------------------
@app.api_route(
    "/gateway/{version}/{endpoint_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    tags=["gateway-runtime"],
)
async def execute_dynamic_gateway_route(
    version: str,
    endpoint_path: str,
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None),
    x_project_id: Optional[str] = Header(default=None, alias="X-Project-ID"),
) -> Response:
    """
    Executes any dynamically registered API endpoint at `/gateway/{version}/{path}`
    with Redis distributed rate limiting, API key verification, lifecycle headers,
    request/response transformations, configurable timeouts, and live analytics telemetry.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    raw_bytes = await request.body()
    parsed_body: Any = None
    if raw_bytes:
        try:
            parsed_body = json.loads(raw_bytes.decode("utf-8"))
        except Exception:
            parsed_body = raw_bytes.decode("utf-8", errors="ignore")

    query_params = dict(request.query_params)
    req_headers = {k: v for k, v in request.headers.items()}

    # Extract API key from X-API-Key header, Bearer token, or ?api_key= query param
    candidate_key = x_api_key or query_params.pop("api_key", None)
    if not candidate_key and authorization and authorization.lower().startswith("bearer ahp_"):
        candidate_key = authorization.split(" ", 1)[1].strip()

    status_code, resp_headers, resp_body, endpoint, latency_ms, cache_hit = (
        gateway_manager.resolve_and_execute(
            version=version,
            path=endpoint_path,
            method=request.method,
            headers=req_headers,
            query_params=query_params,
            body=parsed_body,
            project_id=x_project_id,
        )
    )

    if endpoint is None:
        return JSONResponse(status_code=status_code, content=resp_body, headers=resp_headers)

    project_id = endpoint["project_id"]
    api_key_id: Optional[str] = None
    effective_rpm = int(endpoint["rate_limit_rpm"])

    # Enforce API key authentication if required or if an API key was supplied
    if endpoint["auth_required"] or candidate_key:
        valid_key, key_msg, key_record = security_manager.validate_api_key(
            candidate_key or "", required_scope="gateway:invoke"
        )
        if not valid_key:
            analytics_engine.record_request(
                project_id=project_id,
                endpoint_id=endpoint["id"],
                version=version,
                method=request.method,
                path=endpoint["path"],
                status_code=401,
                latency_ms=latency_ms,
                request_bytes=len(raw_bytes),
                error_category="auth_failed",
                client_ip=client_ip,
            )
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "detail": key_msg},
                headers=resp_headers,
            )
        if key_record:
            api_key_id = key_record["id"]
            effective_rpm = min(effective_rpm, int(key_record["rate_limit_rpm"]))

    # Enforce Redis-backed distributed rate limiting
    rl_bucket = f"ep:{endpoint['id']}:key:{api_key_id or client_ip}"
    rl_decision = redis_store.sliding_window_check(
        bucket_key=rl_bucket,
        limit=effective_rpm,
        window_seconds=60,
    )
    rl_headers = redis_store.build_rate_limit_headers(rl_decision)
    merged_headers = {**resp_headers, **rl_headers}

    if not rl_decision["allowed"]:
        analytics_engine.record_request(
            project_id=project_id,
            endpoint_id=endpoint["id"],
            api_key_id=api_key_id,
            version=version,
            method=request.method,
            path=endpoint["path"],
            status_code=429,
            latency_ms=latency_ms,
            request_bytes=len(raw_bytes),
            error_category="rate_limited",
            client_ip=client_ip,
        )
        AuditLogger.log_event(
            event_type="gateway.rate_limited",
            severity="warning",
            description=f"Rate limit exceeded ({effective_rpm} RPM) on {request.method} /gateway/{version}{endpoint['path']}",
            project_id=project_id,
            actor_ip=client_ip,
        )
        return JSONResponse(
            status_code=429,
            content={
                "error": "Too Many Requests",
                "detail": f"Rate limit of {effective_rpm} requests/minute exceeded",
                "retry_after_seconds": rl_decision["retry_after"],
            },
            headers=merged_headers,
        )

    resp_json_bytes = len(json.dumps(resp_body).encode("utf-8"))
    analytics_engine.record_request(
        project_id=project_id,
        endpoint_id=endpoint["id"],
        api_key_id=api_key_id,
        version=version,
        method=request.method,
        path=endpoint["path"],
        status_code=status_code,
        latency_ms=latency_ms,
        request_bytes=len(raw_bytes),
        response_bytes=resp_json_bytes,
        cache_hit=cache_hit,
        error_category="timeout" if status_code == 504 else None,
        client_ip=client_ip,
    )
    return JSONResponse(status_code=status_code, content=resp_body, headers=merged_headers)


# ---------------------------------------------------------------------------
# v2 Webhooks & Configurable Retry Policies
# ---------------------------------------------------------------------------
@app.post("/api/v2/webhooks", status_code=201, tags=["webhooks"])
def create_webhook(req: WebhookCreateRequest) -> Dict[str, Any]:
    try:
        wh = webhook_manager.register_webhook(
            project_id=req.project_id,
            name=req.name,
            target_url=req.target_url,
            events=req.events,
            secret=req.secret,
            max_retries=req.max_retries,
            backoff_strategy=req.backoff_strategy,
            initial_delay_ms=req.initial_delay_ms,
            timeout_ms=req.timeout_ms,
            actor_id=req.actor_id,
        )
        return {"status": "created", "webhook": wh}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v2/webhooks", tags=["webhooks"])
def list_webhooks(project_id: Optional[str] = None) -> Dict[str, Any]:
    items = webhook_manager.list_webhooks(project_id=project_id)
    return {"count": len(items), "webhooks": items}


@app.post("/api/v2/webhooks/{webhook_id}/trigger", tags=["webhooks"])
def trigger_webhook(webhook_id: str, req: WebhookTriggerRequest) -> Dict[str, Any]:
    try:
        return webhook_manager.dispatch_event(
            webhook_id=webhook_id,
            event_type=req.event_type,
            data=req.data,
            simulate_failures_before_success=req.simulate_failures_before_success,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/v2/webhooks/{webhook_id}/deliveries", tags=["webhooks"])
def list_webhook_deliveries(webhook_id: str) -> Dict[str, Any]:
    deliveries = webhook_manager.list_deliveries(webhook_id)
    return {"count": len(deliveries), "deliveries": deliveries}


# ---------------------------------------------------------------------------
# v2 Live Operational Analytics & Exportable Reports
# ---------------------------------------------------------------------------
@app.get("/api/v2/analytics/summary", tags=["analytics"])
def get_analytics_summary(
    project_id: Optional[str] = None,
    window_minutes: int = Query(default=60, ge=1, le=10080),
) -> Dict[str, Any]:
    return analytics_engine.get_summary(project_id=project_id, window_minutes=window_minutes)


@app.get("/api/v2/analytics/endpoints", tags=["analytics"])
def get_endpoint_performance(project_id: Optional[str] = None) -> Dict[str, Any]:
    perf = analytics_engine.get_endpoint_performance(project_id=project_id)
    return {"count": len(perf), "endpoints": perf}


@app.get("/api/v2/analytics/chart.svg", tags=["analytics"])
def get_analytics_svg_chart(project_id: Optional[str] = None) -> Response:
    svg = analytics_engine.generate_svg_chart(project_id=project_id)
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/api/v2/analytics/export", tags=["analytics"])
def export_analytics_report(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    project_id: Optional[str] = None,
) -> Response:
    content_type, data = analytics_engine.export_report(fmt=format, project_id=project_id)
    ext = "csv" if format.lower() == "csv" else "json"
    headers = {"Content-Disposition": f'attachment; filename="apihub-analytics.{ext}"'}
    if ext == "csv":
        return PlainTextResponse(content=data, media_type=content_type, headers=headers)
    return Response(content=data, media_type=content_type, headers=headers)


# ---------------------------------------------------------------------------
# v2 API Marketplace & Subscription Plans
# ---------------------------------------------------------------------------
@app.get("/api/v2/marketplace/plans", tags=["marketplace"])
def list_subscription_plans() -> Dict[str, Any]:
    plans = marketplace_manager.list_plans()
    return {"count": len(plans), "plans": plans}


@app.post("/api/v2/marketplace/listings", status_code=201, tags=["marketplace"])
def publish_marketplace_api(req: MarketplaceListingRequest) -> Dict[str, Any]:
    try:
        listing = marketplace_manager.publish_marketplace_listing(
            project_id=req.project_id,
            title=req.title,
            summary=req.summary,
            sample_endpoint_path=req.sample_endpoint_path,
            category=req.category,
            version=req.version,
            pricing_plan_required=req.pricing_plan_required,
            price_monthly_usd=req.price_monthly_usd,
            rate_limit_rpm=req.rate_limit_rpm,
            documentation_md=req.documentation_md,
            actor_id=req.actor_id,
        )
        return {"status": "published", "listing": listing}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v2/marketplace/listings", tags=["marketplace"])
def get_marketplace_listings(category: Optional[str] = None) -> Dict[str, Any]:
    listings = marketplace_manager.list_marketplace_listings(category=category)
    return {"count": len(listings), "listings": listings}


@app.post("/api/v2/marketplace/subscribe", status_code=201, tags=["marketplace"])
def subscribe_to_plan_or_listing(req: SubscriptionCreateRequest) -> Dict[str, Any]:
    try:
        sub = marketplace_manager.subscribe_project(
            project_id=req.project_id,
            user_id=req.user_id,
            plan_id=req.plan_id,
            listing_id=req.listing_id,
        )
        return {"status": "subscribed", "subscription": sub}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# v2 Security Monitoring, Audit Trail & Automated Security Auditing
# ---------------------------------------------------------------------------
@app.get("/api/v2/security/audit-logs", tags=["security-audit"])
def list_audit_logs(
    project_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
) -> Dict[str, Any]:
    clauses = ["1=1"]
    params: List[Any] = []
    if project_id:
        clauses.append("project_id = ?")
        params.append(project_id)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    params.append(limit)
    sql = f"SELECT * FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY created_at DESC, rowid DESC LIMIT ?"  # nosec B608
    rows = db.fetch_all(sql, tuple(params))
    logs = [
        {**dict(r), "metadata": json.loads(r["metadata"] or "{}")}
        for r in rows
    ]
    return {"count": len(logs), "audit_logs": logs}


@app.get("/api/v2/security/verify-chain", tags=["security-audit"])
def verify_audit_chain_endpoint() -> Dict[str, Any]:
    return AuditLogger.verify_chain()


@app.post("/api/v2/security/automated-audit", tags=["security-audit"])
@app.get("/api/v2/security/automated-audit", tags=["security-audit"])
def run_automated_security_audit() -> Dict[str, Any]:
    return security_manager.run_automated_security_audit()


# ---------------------------------------------------------------------------
# v2 Infrastructure, Migrations & Demo Bootstrap Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v2/infra/status", tags=["infrastructure"])
def get_infrastructure_status() -> Dict[str, Any]:
    return {
        "app_name": settings.app_name,
        "version": __version__,
        "environment": settings.environment,
        "database": {
            "backend": "postgresql" if settings.is_postgres else "sqlite",
            "current_revision": db.get_current_revision(),
            "available_revisions": MIGRATION_REVISIONS,
            "pool_config": settings.get_sqlalchemy_engine_kwargs(),
        },
        "redis": {
            "backend_mode": redis_store.backend_mode,
            "cache_stats": response_cache.stats(),
        },
        "security_limits": {
            "max_request_body_bytes": settings.max_request_body_bytes,
            "default_gateway_timeout_ms": settings.default_gateway_timeout_ms,
            "login_max_attempts": settings.login_max_attempts,
        },
    }


@app.post("/api/v2/infra/migrate", tags=["infrastructure"])
def trigger_database_migrations(target_revision: str = "head") -> Dict[str, Any]:
    return db.run_migrations(target_revision=target_revision)


@app.post("/api/v2/infra/seed-demo", tags=["infrastructure"])
def seed_demo_endpoint() -> Dict[str, Any]:
    from apihub.seed import seed_demo_workspace

    return seed_demo_workspace()


# ===========================================================================
# APIHub-Pro v3.0 Enterprise Platform Routes
# ===========================================================================
from apihub.ai_gateway import PromptFilterEngine, ai_gateway
from apihub.ddd_cqrs import Query as CQRSQuery, event_store, query_bus
from apihub.dx import dx_engine
from apihub.monetization import monetization_engine
from apihub.observability import prometheus_exporter, trace_collector
from apihub.resilience import resilience_engine
from apihub.threat_security import threat_security_engine


class AIChatCompletionRequest(BaseModel):
    project_id: str
    provider: str = Field(..., description="openai, azure_openai, claude, gemini, or deepseek")
    model: str = Field(default="gpt-4o")
    messages: List[Dict[str, str]]
    redact_pii: bool = True
    block_injections: bool = True
    max_tokens: int = 512
    temperature: float = 0.2


class AIPromptFilterRequest(BaseModel):
    text: str
    redact_pii: bool = True
    block_injections: bool = True


class StripeCheckoutRequest(BaseModel):
    project_id: str
    plan_tier: str = "pro"
    success_url: str = "https://apihub-pro.local/billing/success"
    cancel_url: str = "https://apihub-pro.local/billing/cancel"


class MeteredUsageRequest(BaseModel):
    project_id: str
    metric_type: str = "api_requests"
    quantity: int = 1000
    unit_price_usd: float = 0.0002


class InvoiceGenerateRequest(BaseModel):
    project_id: str
    plan_tier: Optional[str] = None
    auto_pay_via_stripe: bool = True


class CanaryCreateRequest(BaseModel):
    project_id: str
    name: str
    path: str
    method: str = "GET"
    stable_version: str = "v1"
    canary_version: str = "v2"
    canary_weight_percent: int = 20
    auto_rollback_error_pct: float = 15.0


class CanaryRouteRequest(BaseModel):
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, Any] = Field(default_factory=dict)
    body: Any = None
    routing_key: Optional[str] = None
    simulate_canary_error: bool = False


class TrafficShadowRequest(BaseModel):
    project_id: str
    path: str
    method: str = "GET"
    primary_version: str = "v1"
    shadow_version: str = "v2"
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, Any] = Field(default_factory=dict)
    body: Any = None


class ReplayCaptureRequest(BaseModel):
    project_id: str
    version: str = "v2"
    method: str = "GET"
    path: str
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, Any] = Field(default_factory=dict)
    body: Any = None
    original_status: int = 200
    original_latency_ms: float = 5.0


class CircuitBreakerConfigRequest(BaseModel):
    service_name: str
    failure_threshold: int = 3
    recovery_timeout_seconds: int = 30
    half_open_max_calls: int = 2


class CircuitBreakerRecordRequest(BaseModel):
    call_succeeded: Optional[bool] = None
    now_override: Optional[float] = None


class ServiceRegisterRequest(BaseModel):
    service_name: str
    instance_url: str
    version: str = "v1"
    weight: int = 100
    avg_latency_ms: float = 5.0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RiskEvaluateRequest(BaseModel):
    client_ip: str = "127.0.0.1"
    path: str = "/gateway/v2/fx/quotes"
    method: str = "GET"
    user_agent: str = "Mozilla/5.0"
    accept_language: str = "en-US"
    sec_ch_ua: str = ""
    known_fingerprint: Optional[str] = None


class JWTIssueRequest(BaseModel):
    subject: str
    claims: Dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = 3600


class JWTVerifyRequest(BaseModel):
    token: str


class SDKGenerateRequest(BaseModel):
    endpoint_path: str
    method: str = "GET"
    version: str = "v2"
    language: str = "python"
    base_url: str = "http://localhost:8000"


class WebhookSimulateRequest(BaseModel):
    event_type: str = "endpoint.invoked"
    payload: Dict[str, Any] = Field(default_factory=dict)
    secret: str = "whsec_simulator_secret"
    tamper_payload: bool = False


class GraphQLFederationRequest(BaseModel):
    query: str
    variables: Optional[Dict[str, Any]] = None


# --- 1. AI Gateway Endpoints ---
@app.get("/api/v3/ai/models", tags=["v3-ai-gateway"])
def list_ai_gateway_models() -> Dict[str, Any]:
    models = ai_gateway.list_supported_models()
    return {"count": len(models), "models": models}


@app.post("/api/v3/ai/chat/completions", tags=["v3-ai-gateway"])
def ai_gateway_chat_completions(req: AIChatCompletionRequest) -> Response:
    try:
        result = ai_gateway.chat_completion(
            project_id=req.project_id,
            provider=req.provider,
            model=req.model,
            messages=req.messages,
            redact_pii=req.redact_pii,
            block_injections=req.block_injections,
            max_tokens=req.max_tokens,
            temperature=req.temperature,
        )
        status = 400 if result.get("status") == "blocked" else 200
        return JSONResponse(status_code=status, content=result)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v3/ai/filter-check", tags=["v3-ai-gateway"])
def ai_prompt_filter_check(req: AIPromptFilterRequest) -> Dict[str, Any]:
    return PromptFilterEngine.inspect_and_sanitize(
        text=req.text,
        redact_pii=req.redact_pii,
        block_injections=req.block_injections,
    )


@app.get("/api/v3/ai/analytics", tags=["v3-ai-gateway"])
def get_ai_gateway_analytics(project_id: Optional[str] = None) -> Dict[str, Any]:
    return ai_gateway.get_token_and_cost_analytics(project_id=project_id)


# --- 2. Enterprise API Monetization & Stripe Billing Endpoints ---
@app.get("/api/v3/billing/tiers", tags=["v3-monetization"])
def list_monetization_tiers() -> Dict[str, Any]:
    tiers = monetization_engine.list_tiers()
    return {"count": len(tiers), "tiers": tiers}


@app.post("/api/v3/billing/stripe/checkout-session", status_code=201, tags=["v3-monetization"])
def create_stripe_checkout(req: StripeCheckoutRequest) -> Dict[str, Any]:
    try:
        return monetization_engine.create_stripe_checkout_session(
            project_id=req.project_id,
            plan_tier=req.plan_tier,
            success_url=req.success_url,
            cancel_url=req.cancel_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v3/billing/stripe/webhook", tags=["v3-monetization"])
async def handle_stripe_webhook(
    request: Request,
    stripe_signature: Optional[str] = Header(default=None, alias="Stripe-Signature"),
) -> Dict[str, Any]:
    raw_bytes = await request.body()
    payload_str = raw_bytes.decode("utf-8", errors="ignore")
    if not stripe_signature or not monetization_engine.verify_stripe_webhook(
        payload_str, stripe_signature
    ):
        raise HTTPException(status_code=400, detail="Invalid Stripe-Signature header")
    body = json.loads(payload_str or "{}")
    event_type = body.get("type", "invoice.paid")
    return {"received": True, "event_type": event_type, "verified": True}


@app.post("/api/v3/billing/usage", status_code=201, tags=["v3-monetization"])
def record_billing_usage(req: MeteredUsageRequest) -> Dict[str, Any]:
    return monetization_engine.record_metered_usage(
        project_id=req.project_id,
        metric_type=req.metric_type,
        quantity=req.quantity,
        unit_price_usd=req.unit_price_usd,
    )


@app.post("/api/v3/billing/invoices/generate", status_code=201, tags=["v3-monetization"])
def generate_project_invoice(req: InvoiceGenerateRequest) -> Dict[str, Any]:
    return monetization_engine.generate_invoice(
        project_id=req.project_id,
        plan_tier=req.plan_tier,
        auto_pay_via_stripe=req.auto_pay_via_stripe,
    )


@app.get("/api/v3/billing/invoices", tags=["v3-monetization"])
def list_project_invoices(project_id: Optional[str] = None) -> Dict[str, Any]:
    items = monetization_engine.list_invoices(project_id=project_id)
    return {"count": len(items), "invoices": items}


@app.get("/api/v3/billing/revenue", tags=["v3-monetization"])
def get_executive_revenue_analytics() -> Dict[str, Any]:
    return monetization_engine.get_revenue_analytics()


# --- 3. Advanced Gateway Resilience (Canary, Shadowing, Replay, Circuit Breakers, Discovery) ---
@app.post("/api/v3/gateway/canary", status_code=201, tags=["v3-resilience"])
def create_canary(req: CanaryCreateRequest) -> Dict[str, Any]:
    try:
        return resilience_engine.create_canary_deployment(
            project_id=req.project_id,
            name=req.name,
            path=req.path,
            method=req.method,
            stable_version=req.stable_version,
            canary_version=req.canary_version,
            canary_weight_percent=req.canary_weight_percent,
            auto_rollback_error_pct=req.auto_rollback_error_pct,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v3/gateway/canary", tags=["v3-resilience"])
def list_canaries(project_id: Optional[str] = None) -> Dict[str, Any]:
    items = resilience_engine.list_canary_deployments(project_id=project_id)
    return {"count": len(items), "canary_deployments": items}


@app.post("/api/v3/gateway/canary/{canary_id}/route", tags=["v3-resilience"])
def route_canary_call(canary_id: str, req: CanaryRouteRequest) -> Dict[str, Any]:
    try:
        return resilience_engine.route_canary_request(
            canary_id=canary_id,
            headers=req.headers,
            query_params=req.query_params,
            body=req.body,
            routing_key=req.routing_key,
            simulate_canary_error=req.simulate_canary_error,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/v3/gateway/shadow", tags=["v3-resilience"])
def execute_traffic_shadowing(req: TrafficShadowRequest) -> Dict[str, Any]:
    return resilience_engine.execute_shadow_traffic(
        project_id=req.project_id,
        path=req.path,
        method=req.method,
        primary_version=req.primary_version,
        shadow_version=req.shadow_version,
        headers=req.headers,
        query_params=req.query_params,
        body=req.body,
    )


@app.post("/api/v3/gateway/replay/capture", status_code=201, tags=["v3-resilience"])
def capture_request_for_replay(req: ReplayCaptureRequest) -> Dict[str, Any]:
    return resilience_engine.capture_request_for_replay(
        project_id=req.project_id,
        version=req.version,
        method=req.method,
        path=req.path,
        headers=req.headers,
        query_params=req.query_params,
        body=req.body,
        original_status=req.original_status,
        original_latency_ms=req.original_latency_ms,
    )


@app.post("/api/v3/gateway/replay/{capture_id}/execute", tags=["v3-resilience"])
def execute_replayed_request(
    capture_id: str, target_version_override: Optional[str] = None
) -> Dict[str, Any]:
    try:
        return resilience_engine.execute_request_replay(
            capture_id=capture_id,
            target_version_override=target_version_override,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/v3/gateway/circuit-breakers", status_code=201, tags=["v3-resilience"])
def configure_circuit_breaker(req: CircuitBreakerConfigRequest) -> Dict[str, Any]:
    return resilience_engine.configure_circuit_breaker(
        service_name=req.service_name,
        failure_threshold=req.failure_threshold,
        recovery_timeout_seconds=req.recovery_timeout_seconds,
        half_open_max_calls=req.half_open_max_calls,
    )


@app.post("/api/v3/gateway/circuit-breakers/{service_name}/record", tags=["v3-resilience"])
def record_circuit_breaker_call(
    service_name: str, req: CircuitBreakerRecordRequest
) -> Dict[str, Any]:
    return resilience_engine.check_and_record_circuit_breaker(
        service_name=service_name,
        call_succeeded=req.call_succeeded,
        now_override=req.now_override,
    )


@app.post("/api/v3/gateway/discovery/register", status_code=201, tags=["v3-resilience"])
def register_service_discovery_instance(req: ServiceRegisterRequest) -> Dict[str, Any]:
    return resilience_engine.register_service_instance(
        service_name=req.service_name,
        instance_url=req.instance_url,
        version=req.version,
        weight=req.weight,
        avg_latency_ms=req.avg_latency_ms,
        metadata=req.metadata,
    )


@app.get("/api/v3/gateway/discovery/services", tags=["v3-resilience"])
def list_discovered_services(service_name: Optional[str] = None) -> Dict[str, Any]:
    items = resilience_engine.list_services(service_name=service_name)
    return {"count": len(items), "services": items}


@app.post("/api/v3/gateway/discovery/resolve/{service_name}", tags=["v3-resilience"])
def resolve_service_instance(
    service_name: str, strategy: str = "least_latency"
) -> Dict[str, Any]:
    try:
        return resilience_engine.resolve_service_instance(
            service_name=service_name, strategy=strategy
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# --- 4. Advanced Security (Device Fingerprinting, Risk Scoring, Threat Intel, JWT Rotation & JWKS) ---
@app.post("/api/v3/security/evaluate-request", tags=["v3-security"])
def evaluate_request_threat_risk(req: RiskEvaluateRequest) -> Dict[str, Any]:
    return threat_security_engine.evaluate_request_risk(
        client_ip=req.client_ip,
        path=req.path,
        method=req.method,
        user_agent=req.user_agent,
        accept_language=req.accept_language,
        sec_ch_ua=req.sec_ch_ua,
        known_fingerprint=req.known_fingerprint,
    )


@app.get("/api/v3/security/threat-events", tags=["v3-security"])
def list_threat_intel_events(limit: int = 50) -> Dict[str, Any]:
    events = threat_security_engine.list_threat_events(limit=limit)
    return {"count": len(events), "events": events}


@app.get("/.well-known/jwks.json", tags=["v3-security"])
def get_jwks_keystore() -> Dict[str, Any]:
    return threat_security_engine.get_jwks()


@app.post("/api/v3/security/jwt/rotate", tags=["v3-security"])
def rotate_jwt_key(grace_period_seconds: int = 86400) -> Dict[str, Any]:
    return threat_security_engine.rotate_jwt_signing_key(
        grace_period_seconds=grace_period_seconds
    )


@app.post("/api/v3/security/jwt/issue", tags=["v3-security"])
def issue_jwt_token(req: JWTIssueRequest) -> Dict[str, Any]:
    return threat_security_engine.issue_jwt(
        subject=req.subject,
        claims=req.claims,
        ttl_seconds=req.ttl_seconds,
    )


@app.post("/api/v3/security/jwt/verify", tags=["v3-security"])
def verify_jwt_token(req: JWTVerifyRequest) -> Dict[str, Any]:
    return threat_security_engine.verify_jwt(req.token)


# --- 5. Observability (Prometheus Metrics & OpenTelemetry Distributed Traces) ---
@app.get("/metrics", response_class=PlainTextResponse, tags=["v3-observability"])
def get_prometheus_metrics() -> Response:
    content = prometheus_exporter.render_metrics()
    return PlainTextResponse(
        content=content, media_type="text/plain; version=0.0.4; charset=utf-8"
    )


@app.get("/api/v3/observability/traces", tags=["v3-observability"])
def list_distributed_traces(limit: int = 50) -> Dict[str, Any]:
    traces = trace_collector.list_traces(limit=limit)
    return {"count": len(traces), "traces": traces}


@app.get("/api/v3/observability/traces/{trace_id}", tags=["v3-observability"])
def get_distributed_trace(trace_id: str) -> Dict[str, Any]:
    t = trace_collector.get_trace(trace_id)
    if not t:
        raise HTTPException(status_code=404, detail="Trace not found")
    return t


# --- 6. Developer Experience (SDK Generator, Webhook Simulator, GraphQL Federation v2) ---
@app.post("/api/v3/dx/sdk-generate", tags=["v3-dx"])
def generate_client_sdk(req: SDKGenerateRequest) -> Dict[str, Any]:
    return dx_engine.generate_sdk(
        endpoint_path=req.endpoint_path,
        method=req.method,
        version=req.version,
        language=req.language,
        base_url=req.base_url,
    )


@app.post("/api/v3/dx/webhook-simulate", tags=["v3-dx"])
def simulate_webhook_delivery(req: WebhookSimulateRequest) -> Dict[str, Any]:
    return dx_engine.simulate_webhook(
        event_type=req.event_type,
        payload=req.payload,
        secret=req.secret,
        tamper_payload=req.tamper_payload,
    )


@app.post("/api/v3/graphql", tags=["v3-dx"])
def graphql_federation_gateway(req: GraphQLFederationRequest) -> Dict[str, Any]:
    return dx_engine.execute_graphql_query(query=req.query, variables=req.variables)


# --- 7. DDD Event Sourcing & CQRS Endpoints ---
@app.get("/api/v3/architecture/events", tags=["v3-ddd-cqrs"])
def get_domain_event_stream(limit: int = 50) -> Dict[str, Any]:
    return query_bus.ask(CQRSQuery(name="domain.events_summary", params={"limit": limit}))


@app.get("/api/v3/architecture/replay/{aggregate_id}", tags=["v3-ddd-cqrs"])
def replay_aggregate_domain_events(aggregate_id: str) -> Dict[str, Any]:
    return event_store.replay_aggregate_state(aggregate_id)
