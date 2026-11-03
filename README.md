# API-Hub-Pro (`apihub-pro`) v2.0 — Enterprise Dynamic API Gateway, Security, Analytics & Marketplace

**`apihub-pro`** is a full-stack API Gateway, Zero-Trust Security Engine, Live Operational Analytics Platform, and API Marketplace built with Python and FastAPI. Version **2.0.0** introduces dynamic no-code endpoint registration, Redis-backed distributed rate limiting, RBAC & project-level isolation, RFC 6238 TOTP MFA, zero-downtime API key rotation, HMAC-signed webhooks with retry policies, and real-time latency percentile telemetry while preserving 100% backward compatibility with v1 integrations.

---

## Key Features in v2.0

### 1. Advanced API Gateway (`apihub/gateway.py`, `apihub/webhooks.py`)
- **Dynamic API Endpoint Registration:** Create, update, and serve REST endpoints (`/gateway/{version}/{path}`) dynamically at runtime without writing route code.
- **API Versioning & Lifecycle Management:** Manage `v1`, `v2`, and custom versions across `draft` (`403`), `active` (`200`), `deprecated` (injects RFC `Deprecation`, `Sunset`, and `Warning` headers), and `retired` (`410 Gone`) states.
- **Request & Response Transformation Pipeline:** Declarative header injection/removal, JSON body field renaming, sensitive field masking (`***6544`), and envelope wrapping.
- **Configurable Request Timeouts:** Per-endpoint `timeout_ms` enforcement with automatic `504 Gateway Timeout` protection.
- **Webhook Management & Retry Policies:** HMAC-SHA256 webhook signing (`X-APIHub-Signature-256`) with configurable `exponential`, `linear`, or `fixed` retry backoff schedules and delivery logs.

### 2. Zero-Trust Security (`apihub/security.py`, `apihub/rate_limiter.py`)
- **Redis-Backed Distributed Rate Limiting:** Atomic sliding-window rate limiter with `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` headers (with seamless local fallback when offline or on Termux).
- **RBAC & Project-Level Permissions:** Global roles (`admin`, `developer`, `auditor`, `viewer`) combined with per-project access control (`owner`, `editor`, `reader`).
- **API Key Expiration & Grace-Period Rotation:** SHA-256 hashed keys (`ahp_live_...`), configurable expiration TTLs, and zero-downtime rotation (`POST /api/v2/keys/{id}/rotate`) that keeps the previous key active in `rotated_grace` status during the transition window.
- **Login Throttling, MFA & Password Reset:** PBKDF2-HMAC-SHA256 password hashing, brute-force IP/account lockout, RFC 6238 TOTP Multi-Factor Authentication + backup recovery codes, and single-use password reset tokens.
- **Request Size Limits & Abuse Prevention:** Blocks oversized bodies (`413 Payload Too Large`) and SQLi, XSS, and path-traversal payloads (`400 Bad Request`).
- **Tamper-Evident Audit Trail & Automated Security Auditing:** Every security event is chained with `HMAC-SHA256` (`prev_hash` -> `entry_hash`) and continuously audited via `/api/v2/security/automated-audit`.

### 3. Live Analytics & API Marketplace (`apihub/analytics.py`, `apihub/marketplace.py`)
- **Live Operational Telemetry:** Tracks requests per minute (RPM), daily usage, 2xx/4xx/5xx error rates, cache hit ratios, and `p50`, `p90`, `p95`, and `p99` latency percentiles.
- **SVG Charts & Exportable Reports:** Live SVG latency percentile chart (`/api/v2/analytics/chart.svg`) and downloadable CSV and JSON reports (`/api/v2/analytics/export?format=csv|json`).
- **API Marketplace & Subscription Plans:** Tiered plans (`Free`, `Pro`, `Enterprise`), API catalog publishing, and one-click project subscriptions.

### 4. Responsive Web Dashboard (`web/`)
- 8-tab responsive dark-mode interface at `/` and `/dashboard` featuring Live Operational Metrics, Dynamic Gateway Editor, Interactive API Explorer, API Key Rotation, Multi-Project RBAC, API Marketplace, Webhooks, and Security Audit Console.

---

## Quick Start

### Local Development (Linux / macOS / Windows)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
python3 main.py migrate
python3 main.py seed-demo
python3 main.py serve --host 0.0.0.0 --port 8000
```

### Android Termux Setup
```bash
bash scripts/termux-setup.sh
PYTHONPATH=. python3 main.py serve --host 127.0.0.1 --port 8000
```

### Production Docker Compose (PostgreSQL 16 + Redis 7)
```bash
cp .env.example .env
docker compose --profile production up -d --build
```

---

## Running Tests & Security Verification

```bash
# Run full unit & integration test suite
PYTHONPATH=. python3 -m unittest discover -s tests -v

# Run automated security audit CLI
PYTHONPATH=. python3 main.py security-audit
```

See [`docs/API.md`](docs/API.md), [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`SECURITY.md`](SECURITY.md) for complete documentation.
