# APIHub-Pro (`apihub-pro`) v3.0 — Complete REST & GraphQL API Contracts

Every **v1** backward-compatible route, **v2** Advanced Gateway endpoint, and **v3** Enterprise Platform endpoint is documented below.

---

## 1. AI Gateway Endpoints (`v3`)

| Method | Path | Request / Query Contract | Response Contract |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v3/ai/models` | None | `{ "count": 8, "models": [{ "id": "openai/gpt-4o", "provider": "openai", "model": "gpt-4o", "input_cost_per_1k_usd": 0.0025, "output_cost_per_1k_usd": 0.01 }] }` |
| `POST` | `/api/v3/ai/chat/completions` | `{ "project_id": "prj_...", "provider": "openai\|azure_openai\|claude\|gemini\|deepseek", "model": "gpt-4o", "messages": [{"role":"user","content":"..."}], "redact_pii": true, "block_injections": true }` | `{ "id": "ailog_...", "provider": "openai", "filter": {"action":"allowed\|redacted","pii_redacted":false}, "choices": [...], "usage": {"prompt_tokens":12,"completion_tokens":24,"total_tokens":36,"cost_usd":0.00027} }` (`400` on prompt injection) |
| `POST` | `/api/v3/ai/filter-check` | `{ "text": "...", "redact_pii": true, "block_injections": true }` | `{ "allowed": true, "action": "allowed\|redacted\|blocked", "violations": [], "pii_redacted": false, "sanitized_text": "..." }` |
| `GET` | `/api/v3/ai/analytics` | `?project_id=optional` | `{ "total_requests": 6, "blocked_prompts": 1, "pii_redacted_prompts": 5, "tokens": {"prompt_tokens":...,"completion_tokens":...,"total_tokens":...}, "total_cost_usd": 0.0018, "by_provider": {...} }` |

---

## 2. Enterprise API Monetization & Stripe Billing (`v3`)

| Method | Path | Request / Query Contract | Response Contract |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v3/billing/tiers` | None | Lists `free`, `pro`, `enterprise`, and `ai_scale` pricing tiers |
| `POST` | `/api/v3/billing/stripe/checkout-session` | `{ "project_id": "prj_...", "plan_tier": "enterprise" }` | `{ "session_id": "cs_live_...", "checkout_url": "https://checkout.stripe.com/...", "amount_usd": 249.0 }` |
| `POST` | `/api/v3/billing/stripe/webhook` | Header `Stripe-Signature: t=...,v1=...` + raw JSON event | `{ "received": true, "event_type": "invoice.paid", "verified": true }` |
| `POST` | `/api/v3/billing/usage` | `{ "project_id": "prj_...", "metric_type": "api_requests", "quantity": 50000, "unit_price_usd": 0.0002 }` | `{ "id": "usg_...", "total_usd": 10.0 }` |
| `POST` | `/api/v3/billing/invoices/generate` | `{ "project_id": "prj_...", "plan_tier": "pro", "auto_pay_via_stripe": true }` | Itemized invoice with `base_fee_usd`, `metered_usage_usd`, `ai_usage_usd`, `tax_usd`, `total_usd`, and `line_items` |
| `GET` | `/api/v3/billing/invoices` | `?project_id=optional` | Lists generated invoices |
| `GET` | `/api/v3/billing/revenue` | None | `{ "mrr_usd": ..., "arr_usd": ..., "arpu_usd": ..., "collected_invoice_revenue_usd": ..., "metered_overage_revenue_usd": ..., "ai_gateway_revenue_usd": ... }` |

---

## 3. Advanced Gateway Resilience & Service Discovery (`v3`)

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v3/gateway/canary` | Create a weighted canary deployment splitting traffic between `stable_version` and `canary_version` with automatic rollback threshold (`auto_rollback_error_pct`) |
| `GET` | `/api/v3/gateway/canary` | List active and rolled-back canary deployments |
| `POST` | `/api/v3/gateway/canary/{canary_id}/route` | Route a request across stable/canary versions (supports `X-Canary: true` sticky header and automatic rollback on error spike) |
| `POST` | `/api/v3/gateway/shadow` | Mirror a live request to a shadow version and return status & payload comparison diffs |
| `POST` | `/api/v3/gateway/replay/capture` | Capture a request into the `replay_vault` |
| `POST` | `/api/v3/gateway/replay/{capture_id}/execute` | Deterministically replay a captured request against current or target version |
| `POST` | `/api/v3/gateway/circuit-breakers` | Configure a 3-state circuit breaker (`CLOSED` $\rightarrow$ `OPEN` $\rightarrow$ `HALF_OPEN`) |
| `POST` | `/api/v3/gateway/circuit-breakers/{service_name}/record` | Record call success/failure and evaluate circuit breaker state transitions |
| `POST` | `/api/v3/gateway/discovery/register` | Register a microservice instance in the dynamic Service Discovery registry |
| `GET` | `/api/v3/gateway/discovery/services` | List registered microservice instances and latency health |
| `POST` | `/api/v3/gateway/discovery/resolve/{service_name}` | Resolve an optimal instance via `least_latency` or `round_robin` |

---

## 4. Threat Intelligence, Device Fingerprinting & JWKS Rotation (`v3`)

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v3/security/evaluate-request` | Compute `SHA-256` device fingerprint (`fp_...`), evaluate `0–100` risk score against threat intelligence & velocity limits, and return enforcement action (`allow`, `step_up_mfa`, `block`) |
| `GET` | `/api/v3/security/threat-events` | List recorded threat intelligence and API abuse events |
| `GET` | `/.well-known/jwks.json` | Publish active and grace-period public JSON Web Keys (`JWKS`) |
| `POST` | `/api/v3/security/jwt/rotate` | Rotate the active JWT signing key (`kid`) with zero-downtime `rotated_verify_only` grace window |
| `POST` | `/api/v3/security/jwt/issue` | Sign and issue a `kid`-tagged JWT |
| `POST` | `/api/v3/security/jwt/verify` | Verify a JWT across active and grace-period `kid` keys |

---

## 5. Observability, Developer Experience (DX), GraphQL Federation & DDD/CQRS (`v3`)

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/metrics` | Prometheus text exposition format metrics (`apihub_http_requests_total`, `apihub_http_latency_milliseconds`, `apihub_ai_tokens_total`, `apihub_ai_cost_usd_total`, `apihub_circuit_breaker_state`) |
| `GET` | `/api/v3/observability/traces` | List OpenTelemetry W3C `traceparent` distributed traces and child spans |
| `GET` | `/api/v3/observability/traces/{trace_id}` | Inspect a specific distributed trace and its span tree |
| `POST` | `/api/v3/dx/sdk-generate` | Generate client SDK code in `python`, `typescript`, `go`, or `curl` |
| `POST` | `/api/v3/dx/webhook-simulate` | Simulate signed webhook delivery and verify signature tamper detection |
| `POST` | `/api/v3/graphql` | Apollo GraphQL Federation v2 endpoint (`_service { sdl }`, `_entities`, `projects`, `endpoints`, `aiModels`, `analyticsSummary`) |
| `GET` | `/api/v3/architecture/events` | Query the CQRS / Event Sourcing domain event stream |
| `GET` | `/api/v3/architecture/replay/{aggregate_id}` | Reconstruct aggregate state by replaying all immutable `DomainEvent` records |

---

## 6. Preserved v2 & v1 Endpoints (100% Backward Compatible)

- **v1:** `GET /health`, `GET /api/v1/status`, `GET /api/v1/endpoints`, `GET /api/v1/projects`, `GET /api/v1/keys`
- **v2:** `/api/v2/gateway/endpoints`, `/gateway/{version}/{path}`, `/api/v2/auth/*`, `/api/v2/projects/*`, `/api/v2/keys/*`, `/api/v2/webhooks/*`, `/api/v2/analytics/*`, `/api/v2/marketplace/*`, `/api/v2/security/*`, `/api/v2/infra/*`
