# APIHub-Pro (`apihub-pro`) v3.0 — Enterprise AI Gateway, Monetization, Observability & Cloud-Native API Platform

**`apihub-pro`** is a production-grade Enterprise API Management Platform, Multi-Provider AI Gateway, Stripe Monetization Engine, and Zero-Trust Security Gateway built with Python and FastAPI. Version **3.0.0** extends all **v1** and **v2** capabilities with 100% backward compatibility.

---

## Enterprise v3.0 Capabilities Overview

| Pillar | Modules | Key Features Implemented |
| :--- | :--- | :--- |
| **1. Multi-Provider AI Gateway** | `apihub/ai_gateway.py` | Unified routing for **OpenAI** (`gpt-4o`, `gpt-4o-mini`), **Azure OpenAI**, **Anthropic Claude** (`claude-3-7-sonnet`), **Google Gemini** (`gemini-2.5-pro`, `gemini-2.5-flash`), and **DeepSeek** (`deepseek-chat`, `deepseek-reasoner`); real-time prompt injection/jailbreak blocking, automatic PII redaction (`SSN`, cards, keys), token counting, and per-model USD cost tracking |
| **2. Enterprise API Monetization** | `apihub/monetization.py` | **Stripe** Checkout session integration, `Stripe-Signature` HMAC-SHA256 webhook verification, metered API & AI token usage billing, tiered plans (`Free`, `Pro`, `Enterprise`, `AI Scale`), automated itemized invoice generation, and executive revenue analytics (**MRR, ARR, ARPU**) |
| **3. Advanced Gateway & Resilience** | `apihub/gateway.py`, `apihub/resilience.py` | Dynamic no-code endpoints, **Canary deployments** with weighted splitting & automatic error-spike rollback, **Traffic Shadowing** with payload diffing, **Request Replay Vault**, 3-state **Circuit Breakers** (`CLOSED` $ightarrow$ `OPEN` $ightarrow$ `HALF_OPEN`), and **Service Discovery** (`least_latency` / `round_robin`) |
| **4. Zero-Trust Threat Security** | `apihub/security.py`, `apihub/threat_security.py` | Deterministic `SHA-256` **Device Fingerprinting**, continuous `0–100` **Risk Scoring** (`allow`, `step_up_mfa`, `block`), **Threat Intelligence & API Abuse Detection**, **Multi-Key JWT Rotation & JWKS** (`/.well-known/jwks.json`), RFC 6238 TOTP MFA, RBAC, and HMAC-SHA256 hash-chained audit logs |
| **5. Cloud-Native Observability** | `apihub/observability.py`, `deploy/prometheus/`, `deploy/grafana/` | Native **Prometheus** `/metrics` exporter, **OpenTelemetry** W3C `traceparent` distributed tracing & span collector (`/api/v3/observability/traces`), and pre-built **Grafana** dashboard JSON |
| **6. Developer Experience (DX)** | `apihub/dx.py` | **Multi-language SDK Generator** (**Python, TypeScript, Go, cURL**), interactive **Webhook Simulator**, **Apollo GraphQL Federation v2** (`/api/v3/graphql`), and enhanced OpenAPI/Swagger schemas |
| **7. DDD, Event Sourcing & CQRS** | `apihub/ddd_cqrs.py` | Domain-Driven Design bounded contexts, generic Repository pattern, immutable `EventStore` with aggregate replay, and `CommandBus` / `QueryBus` separation |
| **8. Kubernetes & Helm Support** | `deploy/k8s/`, `deploy/helm/apihub-pro/` | Production Kubernetes manifests (`Deployment`, `Service`, `Ingress`, `ConfigMap`, `PodDisruptionBudget`, `HorizontalPodAutoscaler`) and full Helm v3 chart |

---

## Repository Folder Structure

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
├── tests/                     # Unit, Integration & Security test suites (v1, v2, and v3)
├── web/                       # Responsive Web Dashboard (`index.html`, `style.css`, `app.js`)
├── docs/                      # `ARCHITECTURE.md`, `API.md`, `DEPLOYMENT.md`
├── scripts/termux-setup.sh    # Android Termux installation script
├── Dockerfile                 # Hardened non-root production container image
├── docker-compose.yml         # PostgreSQL 16 + Redis 7 + Gateway production stack
└── main.py                    # CLI & server entrypoint
```

---

## Quick Start & Verification

```bash
# Run all v1, v2, and v3 unit, integration, and security tests
PYTHONPATH=. python3 -m unittest discover -s tests -v

# Run database migrations, seed workspace, and execute automated security audit
PYTHONPATH=. python3 main.py migrate
PYTHONPATH=. python3 main.py seed-demo
PYTHONPATH=. python3 main.py security-audit

# Launch server
PYTHONPATH=. python3 main.py serve --host 0.0.0.0 --port 8000
```
