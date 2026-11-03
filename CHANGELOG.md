# Changelog — API-Hub-Pro (`apihub-pro`)

## [2.0.0] — 2026-11-03 (Advanced API Engine Release)

### Added
- **Dynamic API Gateway (`apihub/gateway.py`):** Runtime registration, updating, and execution of API endpoints (`/gateway/{version}/{path}`) without writing route code.
- **API Versioning & Lifecycle Management:** Support for `draft`, `active`, `deprecated` (with automatic `Deprecation` and `Sunset` HTTP headers), and `retired` (`410 Gone`) states.
- **Request & Response Transformation Pipeline:** Declarative header injection/removal, JSON field renaming, sensitive field masking (`***1234`), and response envelope wrapping.
- **Configurable Request Timeouts:** Per-endpoint `timeout_ms` enforcement returning `504 Gateway Timeout` when exceeded.
- **Webhook Management & Retry Policies (`apihub/webhooks.py`):** HMAC-SHA256 webhook payload signing (`X-APIHub-Signature-256`) and configurable `exponential`, `linear`, or `fixed` retry policies with delivery logs.
- **Redis Distributed Rate Limiting & Caching (`apihub/rate_limiter.py`):** Sliding-window rate limiting with `X-RateLimit-*` and `Retry-After` headers plus GET response caching.
- **Enterprise Security (`apihub/security.py`):** Role-based permissions (`admin`, `developer`, `auditor`, `viewer`), project-level access (`owner`, `editor`, `reader`), API key expiration and zero-downtime grace-period rotation, login throttling, RFC 6238 TOTP MFA, password reset tokens, request size limits (`413`), SQLi/XSS/path-traversal abuse prevention (`400`), HMAC-SHA256 hash-chained audit logs, and Automated Security Auditing.
- **Live Operational Analytics (`apihub/analytics.py`):** Real-time RPM, daily usage, `p50`/`p90`/`p95`/`p99` latency percentiles, endpoint error rates, SVG chart generation, and CSV/JSON exportable reports.
- **API Marketplace & Subscription Plans (`apihub/marketplace.py`):** `Free`, `Pro`, and `Enterprise` plans, marketplace API publishing, and project subscription quota upgrades.
- **Responsive Dashboard (`web/`):** 8-tab responsive web interface for live metrics, dynamic endpoint editing, interactive API exploring, key rotation, RBAC management, marketplace browsing, webhooks, and security auditing.
- **Infrastructure:** PostgreSQL production pool configuration, Alembic migrations (`0001_v1_baseline`, `0002_v2_advanced_engine`), Docker Compose `production` profile, GitHub Actions CI, and Termux setup script.

### Preserved
- **100% v1 Backward Compatibility:** Retained `/health`, `/api/v1/status`, `/api/v1/endpoints`, `/api/v1/projects`, and `/api/v1/keys`.
