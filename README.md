<div align="center">

# APIHub-Pro (`apihub-pro`) v3.0

### Enterprise AI Gateway · API Monetization · Cloud-Native Observability · Zero-Trust API Management Platform

[![CI & Security Audit](https://github.com/MrKhan025/apihub-pro/actions/workflows/ci.yml/badge.svg)](https://github.com/MrKhan025/apihub-pro/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/release-v3.0.0-0284c7?style=flat-square)](https://github.com/MrKhan025/apihub-pro)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-38bdf8?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Enterprise%20Gateway-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![AI Gateway](https://img.shields.io/badge/AI%20Gateway-OpenAI%20%7C%20Azure%20%7C%20Claude%20%7C%20Gemini%20%7C%20DeepSeek-6366f1?style=flat-square)](docs/API.md)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Helm%20%2B%20HPA-326ce5?style=flat-square&logo=kubernetes&logoColor=white)](deploy/k8s/)
[![Security](https://img.shields.io/badge/Security-Zero--Trust%20%2B%20JWKS%20%2B%20MFA-10b981?style=flat-square)](SECURITY.md)
[![Termux](https://img.shields.io/badge/Android-Termux%20Ready-22c55e?style=flat-square&logo=android&logoColor=white)](scripts/termux-setup.sh)
[![License: MIT](https://img.shields.io/badge/License-MIT-f59e0b?style=flat-square)](LICENSE)

**APIHub-Pro** is a production-grade, self-hosted **Enterprise API Gateway, Multi-Provider AI Gateway, Stripe Monetization Engine, and Zero-Trust Security Platform**. It enables engineering teams to dynamically register and version REST/GraphQL APIs without writing route boilerplate, route and govern LLM traffic across 5 AI providers with real-time PII redaction and cost tracking, monetize APIs with Stripe metered billing, and deploy anywhere from **Android Termux** to **Kubernetes with Horizontal Pod Autoscaling (HPA)**.

[Architecture](docs/ARCHITECTURE.md) · [API Reference](docs/API.md) · [OS Installation Guide](INSTALLATION.md) · [Deployment Guide](docs/DEPLOYMENT.md) · [Security Policy](SECURITY.md)

</div>

---

## System Architecture

```text
                        +---------------------------------------------------+
                        |        Clients / AI Agents / SDKs / GraphQL       |
                        +-------------------------+-------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                            APIHub-Pro v3.0 Edge & Security Perimeter                              |
|  - OpenTelemetry W3C Trace Context (`traceparent` / `X-Trace-Id`)                                 |
|  - Device Fingerprinting (`SHA-256`) + Continuous 0-100 Threat Risk Scoring (`allow`/`mfa`/`block`)|
|  - Multi-Key JWKS (`/.well-known/jwks.json`) + Scoped API Key Rotation (`ahp_live_...`)           |
|  - Distributed Redis Sliding-Window Rate Limiter (`X-RateLimit-*` / `Retry-After`)                |
+-------------------------+-----------------------------------+-------------------------------------+
                          |                                   |
          +---------------+---------------+                   +-----------------+-----------------+
          |                               |                                     |
          v                               v                                     v
+-------------------+           +-------------------+                 +-------------------+
| Dynamic API       |           | Multi-Provider    |                 | GraphQL Federation|
| Gateway & Traffic |           | AI Gateway Engine |                 | v2 & DX Engine    |
| Resilience        |           | (`ai_gateway.py`) |                 | (`dx.py`)         |
| (`gateway.py`,    |           | - OpenAI          |                 | - Apollo SDL v2.3 |
|  `resilience.py`) |           | - Azure OpenAI    |                 | - Python/TS/Go SDK|
| - Canary Splits   |           | - Claude          |                 | - Webhook Sim     |
| - Traffic Shadow  |           | - Gemini          |                 +-------------------+
| - Request Replay  |           | - DeepSeek        |
| - Circuit Breaker |           | - Prompt Filter   |
| - Service Discov. |           | - Token/USD Cost  |
+---------+---------+           +---------+---------+
          |                               |
          +---------------+---------------+
                          |
                          v
+---------------------------------------------------------------------------------------------------+
|                 DDD Bounded Contexts, Repository Layer, Event Sourcing & CQRS                     |
|  - `CommandBus` (Write Side) -> Appends immutable `DomainEvent` records to `EventStore`           |
|  - `QueryBus` (Read Side)    -> Serves low-latency analytics, revenue, and trace projections      |
|  - `MonetizationEngine`      -> Stripe Checkout, `Stripe-Signature` Webhooks, Usage Invoices, MRR |
|  - `Observability`           -> Prometheus `/metrics`, Grafana Dashboards, Distributed Traces     |
+---------------------------------------------------------------------------------------------------+
```

---

## Enterprise Capabilities Matrix

| Domain Pillar | Core Modules | Key Production Capabilities |
| :--- | :--- | :--- |
| **1. Multi-Provider AI Gateway** | `apihub/ai_gateway.py` | Unified completions & model catalog for **OpenAI** (`gpt-4o`, `gpt-4o-mini`), **Azure OpenAI** (`azure/gpt-4o`), **Anthropic Claude** (`claude-3-7-sonnet`), **Google Gemini** (`gemini-2.5-pro`, `gemini-2.5-flash`), and **DeepSeek** (`deepseek-chat`, `deepseek-reasoner`); real-time prompt injection/jailbreak blocking, automatic PII redaction (`SSN`, cards, keys), token analytics, and per-model USD cost tracking |
| **2. Enterprise API Monetization** | `apihub/monetization.py` | **Stripe** Checkout session creation, `Stripe-Signature` HMAC-SHA256 webhook verification, metered API request & AI token billing, tiered plans (`Free`, `Pro`, `Enterprise`, `AI Scale`), automated itemized invoice generation, and executive revenue analytics (**MRR, ARR, ARPU**) |
| **3. Dynamic Gateway & Resilience** | `apihub/gateway.py`, `apihub/resilience.py` | Runtime no-code route registration (`/gateway/{version}/{path}`), lifecycle management (`draft`, `active`, `deprecated`, `retired`), request/response transformations, configurable timeouts (`504`), weighted **Canary deployments** with auto-rollback, **Traffic Shadowing**, **Request Replay Vault**, 3-state **Circuit Breakers** (`CLOSED` $\rightarrow$ `OPEN` $\rightarrow$ `HALF_OPEN`), and **Service Discovery** |
| **4. Zero-Trust Threat Security** | `apihub/security.py`, `apihub/threat_security.py` | Deterministic `SHA-256` **Device Fingerprinting**, continuous `0–100` **Risk Scoring** (`allow`, `step_up_mfa`, `block`), **Threat Intelligence & API Abuse Detection**, **Multi-Key JWT Rotation & JWKS** (`/.well-known/jwks.json`), zero-downtime API key rotation (`rotated_grace`), RFC 6238 TOTP MFA, RBAC, and HMAC-SHA256 hash-chained audit logs |
| **5. Cloud-Native Observability** | `apihub/observability.py`, `apihub/analytics.py` | Native **Prometheus** `/metrics` exporter, **OpenTelemetry** W3C `traceparent` distributed tracing & span collector (`/api/v3/observability/traces`), pre-built **Grafana** dashboard JSON, live `p50`/`p90`/`p95`/`p99` latency percentiles, SVG charts, and CSV/JSON exports |
| **6. Developer Experience (DX)** | `apihub/dx.py`, `web/` | On-demand client **SDK Generator** (**Python, TypeScript, Go, cURL**), interactive **Webhook Simulator**, **Apollo GraphQL Federation v2** (`POST /api/v3/graphql`), and an 11-tab responsive dark-mode Web Dashboard (`/dashboard`) |
| **7. DDD, Event Sourcing & CQRS** | `apihub/ddd_cqrs.py` | Domain-Driven Design bounded contexts, generic `BaseRepository[T]`, append-only hash-chained `EventStore` (`domain_events` table) with aggregate state replay, and `CommandBus` / `QueryBus` separation |
| **8. Kubernetes, Docker & Termux** | `deploy/k8s/`, `deploy/helm/`, `Dockerfile` | Production Kubernetes manifests (`Deployment`, `Service`, `Ingress`, `ConfigMap`, `PodDisruptionBudget`, `HorizontalPodAutoscaler`), Helm v3 chart, PostgreSQL 16 + Redis 7 Docker Compose stack, and Android Termux installer |

---

## Step-by-Step Execution Guide by Operating System

### 1. Windows 10 / Windows 11 (PowerShell)

```powershell
# 1. Clone the repository
git clone https://github.com/MrKhan025/apihub-pro.git
cd apihub-pro

# 2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt

# 4. Initialize configuration, database migrations & demo workspace
Copy-Item .env.example .env
$env:PYTHONPATH="."
python main.py migrate
python main.py seed-demo

# 5. Run unit/integration/security tests (20 tests) & security audit
python -m unittest discover -s tests -v
python main.py security-audit

# 6. Start the APIHub-Pro server
python main.py serve --host 127.0.0.1 --port 8000
```

### 2. Linux (Ubuntu / Debian / Kali / Fedora / Arch)

```bash
# 1. Install Python & Git (Ubuntu/Debian example)
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git sqlite3

# 2. Clone the repository & set up virtual environment
git clone https://github.com/MrKhan025/apihub-pro.git
cd apihub-pro
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt

# 4. Run database migrations, seed demo data & verify test suite
cp .env.example .env
PYTHONPATH=. python3 main.py migrate
PYTHONPATH=. python3 main.py seed-demo
PYTHONPATH=. python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 main.py security-audit

# 5. Launch server
PYTHONPATH=. python3 main.py serve --host 0.0.0.0 --port 8000
```

### 3. macOS (Intel & Apple Silicon M1 / M2 / M3 / M4)

```bash
# 1. Install Python 3.11+ via Homebrew if needed
brew install python@3.11 git

# 2. Clone & install in virtual environment
git clone https://github.com/MrKhan025/apihub-pro.git
cd apihub-pro
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt

# 3. Migrate, seed, test & start server
cp .env.example .env
PYTHONPATH=. python3 main.py migrate
PYTHONPATH=. python3 main.py seed-demo
PYTHONPATH=. python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 main.py serve --host 127.0.0.1 --port 8000
```

### 4. Android Termux (Mobile ARM64)

```bash
# 1. Install Termux packages
pkg update -y && pkg install -y python git sqlite redis

# 2. Clone repository and run the automated Termux installer
git clone https://github.com/MrKhan025/apihub-pro.git
cd apihub-pro
bash scripts/termux-setup.sh

# 3. Launch server and open http://127.0.0.1:8000/dashboard in mobile browser
source .venv/bin/activate
PYTHONPATH=. python3 main.py serve --host 127.0.0.1 --port 8000
```

### 5. Docker Compose Production Profile (PostgreSQL 16 + Redis 7)

```bash
cp .env.example .env
# Edit .env with your production POSTGRES_PASSWORD and secret keys
docker compose --profile production up -d --build
curl http://localhost:8000/health
```

### 6. Kubernetes & Helm v3 Deployment

```bash
# Deploy Kubernetes manifests (Namespace, ConfigMap, Deployment, Service, HPA, Ingress, PDB)
kubectl apply -f deploy/k8s/

# Or deploy via Helm v3
helm upgrade --install apihub-pro ./deploy/helm/apihub-pro --namespace apihub-pro --create-namespace
```

---

## Repository Directory Structure

```text
apihub-pro/
├── apihub/
│   ├── __init__.py            # Package metadata
│   ├── config.py              # PostgreSQL pool, Redis, Security & Gateway settings
│   ├── database.py            # Relational engine & Alembic revision runner (0001 -> 0003)
│   ├── ddd_cqrs.py            # DDD Repositories, Event Sourcing Store & CQRS Buses
│   ├── ai_gateway.py          # OpenAI, Azure, Claude, Gemini, DeepSeek + Prompt Filter & Cost
│   ├── monetization.py        # Stripe Checkout, Webhooks, Metered Billing, Invoices & MRR/ARR
│   ├── resilience.py          # Canary, Traffic Shadowing, Request Replay, Circuit Breakers, Discovery
│   ├── threat_security.py     # Device Fingerprinting, Risk Scoring, Threat Intel & JWKS Rotation
│   ├── observability.py       # Prometheus /metrics exporter & OpenTelemetry W3C Trace Collector
│   ├── dx.py                  # Python/TS/Go/cURL SDK Generator, Webhook Simulator & GraphQL Federation
│   ├── gateway.py             # Dynamic endpoint registration, versioning, lifecycle & transforms
│   ├── security.py            # RBAC, MFA (TOTP), API key rotation, audit chain & security auditor
│   ├── rate_limiter.py        # Redis-backed distributed sliding-window rate limiter & cache
│   ├── analytics.py           # Live RPM, latency percentiles (p50/p90/p95/p99), SVG chart & CSV export
│   ├── marketplace.py         # Multi-project workspaces, plans & API marketplace catalog
│   ├── webhooks.py            # HMAC-SHA256 webhook signing & exponential/linear retry engine
│   ├── seed.py                # Idempotent demo workspace initializer
│   ├── api.py                 # FastAPI application exposing all v1, v2, and v3 routes
│   └── cli.py                 # CLI (`serve`, `migrate`, `seed-demo`, `security-audit`, `export-report`)
├── deploy/
│   ├── k8s/                   # Kubernetes production manifests (Deployment, HPA, Ingress, PDB, etc.)
│   ├── helm/apihub-pro/       # Helm v3 Chart (`Chart.yaml`, `values.yaml`, `templates/`)
│   ├── prometheus/            # `prometheus.yml` scrape configuration
│   └── grafana/               # `apihub-pro-dashboard.json` Grafana observability dashboard
├── migrations/                # Alembic migrations (`0001_v1_baseline`, `0002_v2_advanced_engine`, `0003_v3_enterprise_platform`)
├── tests/                     # 20 Unit, Integration & Security test suites across 7 modules
├── web/                       # 11-Tab Responsive Web Dashboard (`index.html`, `style.css`, `app.js`)
├── docs/                      # `ARCHITECTURE.md`, `API.md`, `DEPLOYMENT.md`
├── scripts/termux-setup.sh    # Android Termux installation script
├── INSTALLATION.md            # Detailed OS-by-OS installation & execution guide
├── CONTRIBUTING.md            # Developer workflow & quality gate rules
├── SECURITY.md                # Zero-Trust security & cryptographic policy
├── CHANGELOG.md               # Release history (v1.0 -> v2.0 -> v3.0)
├── LICENSE                    # MIT License
├── Makefile                   # Developer command shortcuts
├── Dockerfile                 # Hardened non-root production container image
├── docker-compose.yml         # PostgreSQL 16 + Redis 7 + Gateway production stack
└── main.py                    # CLI & server entrypoint
```

---

## Key REST & GraphQL Endpoints Overview

| Category | Endpoint | Purpose |
| :--- | :--- | :--- |
| **Dashboard & Health** | `GET /dashboard`, `GET /health`, `GET /metrics` | 11-tab Web UI, health probe, and Prometheus metrics |
| **AI Gateway (`v3`)** | `POST /api/v3/ai/chat/completions`, `GET /api/v3/ai/models`, `GET /api/v3/ai/analytics` | Unified OpenAI/Azure/Claude/Gemini/DeepSeek completion, PII redaction, token & USD cost tracking |
| **Monetization (`v3`)** | `POST /api/v3/billing/stripe/checkout-session`, `POST /api/v3/billing/invoices/generate`, `GET /api/v3/billing/revenue` | Stripe Checkout, webhook verification, metered billing, invoices, and MRR/ARR/ARPU |
| **Resilience (`v3`)** | `POST /api/v3/gateway/canary`, `POST /api/v3/gateway/shadow`, `POST /api/v3/gateway/replay/capture`, `POST /api/v3/gateway/circuit-breakers`, `POST /api/v3/gateway/discovery/register` | Canary traffic splits, shadow mirroring, request replay, circuit breakers, and service discovery |
| **Threat Security (`v3`)** | `POST /api/v3/security/evaluate-request`, `GET /.well-known/jwks.json`, `POST /api/v3/security/jwt/rotate` | Device fingerprinting, 0–100 risk score, threat intel, and multi-key JWT rotation |
| **DX & GraphQL (`v3`)** | `POST /api/v3/dx/sdk-generate`, `POST /api/v3/dx/webhook-simulate`, `POST /api/v3/graphql` | Python/TS/Go/cURL SDK generator, webhook simulator, and Apollo GraphQL Federation v2 |
| **Core Gateway (`v2`/`v1`)** | `POST /api/v2/gateway/endpoints`, `ANY /gateway/{version}/{path}`, `POST /api/v2/keys/{id}/rotate`, `POST /api/v2/security/automated-audit` | Dynamic route creation, runtime execution, zero-downtime key rotation, and security auditing |

---

## License

Released under the [MIT License](LICENSE).
