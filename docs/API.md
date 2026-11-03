# API-Hub-Pro (`apihub-pro`) v2.0 — Complete REST API Reference

Every v1 backward-compatible route and v2.0 Advanced API Engine endpoint is documented below.

---

## 1. Backward-Compatible v1 Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Returns service health, active database migration revision, and Redis backend status |
| `GET` | `/api/v1/status` | Legacy v1 status check (`backward_compatible: true`) |
| `GET` | `/api/v1/endpoints` | Lists registered endpoints (`?project_id=optional`) |
| `GET` | `/api/v1/projects` | Lists configured API projects |
| `GET` | `/api/v1/keys` | Lists API key metadata without exposing secret hashes |

---

## 2. Dynamic API Gateway & Runtime Execution (`v2`)

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v2/gateway/endpoints` | Dynamically register a new API endpoint without writing route code. Supports `version`, `lifecycle_state` (`draft`, `active`, `deprecated`, `retired`), `timeout_ms`, `cache_ttl_seconds`, `request_transform`, and `response_transform`. |
| `GET` | `/api/v2/gateway/endpoints` | List dynamic endpoints filtered by `project_id`, `version`, or `lifecycle_state`. |
| `GET` | `/api/v2/gateway/endpoints/{endpoint_id}` | Retrieve full configuration of a single dynamic endpoint. |
| `PUT` | `/api/v2/gateway/endpoints/{endpoint_id}` | Update endpoint version, lifecycle state, timeout, or transformation rules in place. |
| `DELETE` | `/api/v2/gateway/endpoints/{endpoint_id}` | Remove a dynamic endpoint and record an audit log entry. |
| `ANY` | `/gateway/{version}/{endpoint_path:path}` | **Dynamic Runtime Dispatcher:** Executes any registered `GET`, `POST`, `PUT`, `PATCH`, or `DELETE` endpoint. Enforces API keys (`X-API-Key` or `Bearer`), Redis sliding-window rate limits (`X-RateLimit-*` headers), lifecycle headers (`Deprecation`, `Sunset`, `410 Gone`), transformations, and timeouts (`504 Gateway Timeout`). |

---

## 3. Security, Authentication, RBAC, MFA & API Key Rotation (`v2`)

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v2/auth/register` | Create a new user with RBAC role (`admin`, `developer`, `auditor`, `viewer`). |
| `POST` | `/api/v2/auth/login` | Authenticate user with brute-force IP/account throttling and optional `totp_code`. |
| `POST` | `/api/v2/auth/mfa/setup` | Provision RFC 6238 TOTP secret, `otpauth://` URI, and 6 single-use backup recovery codes. |
| `POST` | `/api/v2/auth/mfa/verify` | Verify a 6-digit TOTP code and activate mandatory MFA on the user account. |
| `POST` | `/api/v2/auth/password-reset/request` | Issue a time-bound, single-use password reset token. |
| `POST` | `/api/v2/auth/password-reset/confirm` | Redeem a password reset token to set a new password and clear lockouts. |
| `GET` | `/api/v2/users` | List registered users, RBAC roles, permissions, and MFA status. |
| `POST` | `/api/v2/projects` | Create a multi-project workspace with plan quotas (`free`, `pro`, `enterprise`). |
| `GET` | `/api/v2/projects` | List projects accessible to a user. |
| `GET` | `/api/v2/projects/{project_id}` | Inspect project details and RBAC member list (`owner`, `editor`, `reader`). |
| `POST` | `/api/v2/projects/{project_id}/members` | Grant or update project-level access (`owner`, `editor`, `reader`) for a user. |
| `POST` | `/api/v2/keys` | Issue a scoped API key (`ahp_live_...`) with configurable RPM and expiration TTL. |
| `GET` | `/api/v2/keys` | List API keys and rotation status. |
| `POST` | `/api/v2/keys/{key_id}/rotate` | Zero-downtime API key rotation: issues a new key immediately while keeping the old key valid in `rotated_grace` status during `grace_period_seconds`. |
| `POST` | `/api/v2/keys/{key_id}/revoke` | Immediately revoke an API key. |
| `GET` | `/api/v2/security/audit-logs` | Query tamper-evident HMAC-SHA256 hash-chained security audit trail. |
| `GET` | `/api/v2/security/verify-chain` | Cryptographically verify every link (`prev_hash` -> `entry_hash`) in the audit log chain. |
| `POST` | `/api/v2/security/automated-audit` | Execute automated security auditing across keys, endpoints, MFA, timeouts, and audit chain. |

---

## 4. Webhooks & Retry Policies (`v2`)

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v2/webhooks` | Register a project webhook with HMAC-SHA256 signing secret and retry policy (`exponential`, `linear`, `fixed`). |
| `GET` | `/api/v2/webhooks` | List configured webhooks for a project. |
| `POST` | `/api/v2/webhooks/{webhook_id}/trigger` | Dispatch an event with `X-APIHub-Signature-256` header and automatic retry execution. |
| `GET` | `/api/v2/webhooks/{webhook_id}/deliveries` | Inspect delivery attempts, HTTP status codes, latencies, and backoff schedules. |

---

## 5. Live Operational Analytics & Marketplace (`v2`)

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v2/analytics/summary` | Retrieve total requests, current/average RPM, 2xx/4xx/5xx breakdown, error rate %, `p50`/`p90`/`p95`/`p99` latency percentiles, RPM time series, and daily usage. |
| `GET` | `/api/v2/analytics/endpoints` | Per-endpoint request volume, error rate, cache hit rate, and latency percentiles. |
| `GET` | `/api/v2/analytics/chart.svg` | Live SVG latency percentile bar chart. |
| `GET` | `/api/v2/analytics/export` | Export analytics report as downloadable CSV (`?format=csv`) or JSON (`?format=json`). |
| `GET` | `/api/v2/marketplace/plans` | List available subscription plans (`Free`, `Pro`, `Enterprise`) and quotas. |
| `POST` | `/api/v2/marketplace/listings` | Publish an API product to the API Marketplace catalog. |
| `GET` | `/api/v2/marketplace/listings` | Browse published API Marketplace products (`?category=optional`). |
| `POST` | `/api/v2/marketplace/subscribe` | Subscribe a project to a subscription tier or marketplace listing and upgrade quotas. |

---

## 6. Infrastructure & Database Migrations (`v2`)

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v2/infra/status` | Inspect PostgreSQL/SQLite pool settings, Alembic migration state, Redis mode, and security limits. |
| `POST` | `/api/v2/infra/migrate` | Apply Alembic database schema migrations up to `head`. |
| `POST` | `/api/v2/infra/seed-demo` | Idempotently initialize demo users, projects, dynamic endpoints, marketplace APIs, and metrics. |
