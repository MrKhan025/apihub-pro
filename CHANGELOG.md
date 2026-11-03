# Changelog — APIHub-Pro (`apihub-pro`)

## [3.0.0] — 2026-11-03 (Enterprise AI Gateway, Monetization, Observability & Cloud-Native Platform)

### Added
- **Multi-Provider AI Gateway (`apihub/ai_gateway.py`):** Unified completions and model catalog for **OpenAI**, **Azure OpenAI**, **Anthropic Claude**, **Google Gemini**, and **DeepSeek** with real-time prompt injection/jailbreak blocking, automatic PII redaction, token analytics, and USD cost tracking.
- **Enterprise API Monetization (`apihub/monetization.py`):** **Stripe** Checkout session creation, `Stripe-Signature` HMAC-SHA256 webhook verification, metered usage billing, tiered plans (`Free`, `Pro`, `Enterprise`, `AI Scale`), itemized invoice generation, and executive revenue analytics (**MRR, ARR, ARPU**).
- **Advanced Gateway Resilience (`apihub/resilience.py`):** Weighted **Canary deployments** with automatic rollback on error spikes, **Traffic Shadowing** with payload diffing, **Request Replay Vault**, 3-state **Circuit Breakers** (`CLOSED` $\rightarrow$ `OPEN` $\rightarrow$ `HALF_OPEN`), and dynamic **Service Discovery** (`least_latency` / `round_robin`).
- **Threat Intelligence & JWKS Security (`apihub/threat_security.py`):** `SHA-256` **Device Fingerprinting**, continuous `0–100` **Risk Scoring**, **Threat Intelligence & API Abuse Detection**, and **Multi-Key JWT Key Rotation & JWKS** (`/.well-known/jwks.json`).
- **Observability (`apihub/observability.py`, `deploy/`):** Native **Prometheus** `/metrics` exporter, **OpenTelemetry** W3C `traceparent` distributed tracing, and **Grafana** dashboard JSON.
- **Developer Experience (`apihub/dx.py`):** Multi-language **SDK Generator** (`Python`, `TypeScript`, `Go`, `cURL`), **Webhook Simulator**, and **Apollo GraphQL Federation v2** (`POST /api/v3/graphql`).
- **DDD, Repository Pattern, Event Sourcing & CQRS (`apihub/ddd_cqrs.py`):** Immutable `DomainEvent` store, aggregate state replay, generic `BaseRepository`, `CommandBus`, and `QueryBus`.
- **Kubernetes & Helm Support (`deploy/k8s/`, `deploy/helm/apihub-pro/`):** Production Kubernetes manifests (`Deployment`, `Service`, `Ingress`, `ConfigMap`, `PodDisruptionBudget`, `HorizontalPodAutoscaler`) and Helm v3 chart.

## [2.0.0] — 2026-11-03 (Advanced API Engine Release)
- Dynamic API endpoint registration, versioning, lifecycle management, request/response transforms, configurable timeouts, webhooks with retries, Redis rate limiting, RBAC, TOTP MFA, API key rotation, percentile analytics, and API marketplace.
