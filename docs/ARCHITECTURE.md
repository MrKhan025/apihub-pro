# Architecture Overview — API-Hub-Pro (`apihub-pro`) v2.0

## System Layers

1. **Dynamic API Gateway Layer (`apihub/gateway.py`)**
   - Stores endpoint definitions in `dynamic_endpoints` so new routes are created, versioned (`v1`, `v2`, etc.), and updated at runtime without code changes or restarts.
   - Enforces lifecycle states (`draft` -> `403`, `active` -> `200`, `deprecated` -> injects RFC `Deprecation`, `Sunset`, and `Warning` headers, `retired` -> `410 Gone`).
   - Runs declarative request & response transformations (`TransformPipeline`) and enforces per-endpoint `timeout_ms` (`504 Gateway Timeout`).

2. **Distributed Redis Rate Limiter & Cache (`apihub/rate_limiter.py`)**
   - Implements atomic sliding-window rate limiting backed by Redis sorted sets (`ZREMRANGEBYSCORE` + `ZADD` + `ZCARD`) with automatic failover to an in-memory store for offline/Termux execution.
   - Emits `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` headers on every gateway call.

3. **Zero-Trust Security & RBAC (`apihub/security.py`)**
   - **Authentication:** PBKDF2-HMAC-SHA256 (120,000 iterations), IP + account brute-force lockout, RFC 6238 TOTP MFA + single-use recovery codes, and time-bound password reset tokens.
   - **Authorization:** Global RBAC roles (`admin`, `developer`, `auditor`, `viewer`) + per-project access control (`owner`, `editor`, `reader`).
   - **API Key Lifecycle:** SHA-256 hashed key storage, scoped permissions, expiration timestamps, and grace-period rotation (`rotated_grace`).
   - **Audit Chain:** Every security and configuration change is chained with `HMAC-SHA256` (`prev_hash` -> `entry_hash`).

4. **Live Analytics & API Marketplace (`apihub/analytics.py`, `apihub/marketplace.py`)**
   - Captures request latency, status codes, cache hits, and byte volume to compute real-time RPM, daily usage, and `p50`/`p90`/`p95`/`p99` percentiles.
   - Provides tiered subscription plans (`Free`, `Pro`, `Enterprise`) and a searchable API Marketplace.
