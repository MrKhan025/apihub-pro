"""
Security, Developer Experience (DX), Observability & DDD/CQRS Tests for APIHub-Pro v3.0:
- Device fingerprinting, 0-100 risk scoring, threat intelligence & API abuse detection
- Multi-key JWT signing key rotation & JWKS (`/.well-known/jwks.json`)
- Prometheus `/metrics` & OpenTelemetry W3C `traceparent` distributed tracing
- Multi-language SDK generator, Webhook simulator & GraphQL Federation v2
- DDD Event Sourcing stream & aggregate state replay
"""

from __future__ import annotations

import unittest
from fastapi.testclient import TestClient

from apihub.api import app
from apihub.database import db
from apihub.rate_limiter import redis_store
from apihub.seed import seed_demo_workspace


class TestV3SecurityDXAndObservability(unittest.TestCase):
    def setUp(self) -> None:
        db.reset_all()
        redis_store.flush_all()
        self.client = TestClient(app)
        self.seed = seed_demo_workspace()

    def test_device_fingerprinting_risk_scoring_and_threat_intel(self) -> None:
        # Low-risk normal browser request
        low_res = self.client.post(
            "/api/v3/security/evaluate-request",
            json={
                "client_ip": "10.10.1.5",
                "path": "/gateway/v2/fx/quotes",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)",
            },
        ).json()
        self.assertEqual(low_res["risk_level"], "low")
        self.assertEqual(low_res["action"], "allow")
        self.assertTrue(low_res["device_fingerprint"].startswith("fp_"))

        # High/Critical risk request from known threat IP + malicious scanner User-Agent + fingerprint drift
        crit_res = self.client.post(
            "/api/v3/security/evaluate-request",
            json={
                "client_ip": "198.51.100.66",
                "path": "/api/v2/auth/login",
                "user_agent": "sqlmap/1.8",
                "known_fingerprint": low_res["device_fingerprint"],
            },
        ).json()
        self.assertEqual(crit_res["risk_level"], "critical")
        self.assertEqual(crit_res["action"], "block")
        self.assertGreaterEqual(crit_res["risk_score"], 85)

        events = self.client.get("/api/v3/security/threat-events").json()
        self.assertGreaterEqual(events["count"], 2)

    def test_jwt_key_rotation_and_jwks_verification(self) -> None:
        issued_1 = self.client.post(
            "/api/v3/security/jwt/issue",
            json={"subject": "usr_enterprise_1", "claims": {"scope": "gateway:admin"}},
        ).json()
        token_1 = issued_1["token"]
        kid_1 = issued_1["kid"]

        # Rotate JWT signing key
        rotated = self.client.post("/api/v3/security/jwt/rotate").json()
        kid_2 = rotated["kid"]
        self.assertNotEqual(kid_1, kid_2)

        # Issue second token with new key
        issued_2 = self.client.post(
            "/api/v3/security/jwt/issue",
            json={"subject": "usr_enterprise_2"},
        ).json()
        token_2 = issued_2["token"]

        # Both token_1 (rotated_verify_only grace key) and token_2 (active key) must verify cleanly
        v1 = self.client.post("/api/v3/security/jwt/verify", json={"token": token_1}).json()
        self.assertTrue(v1["valid"])
        self.assertEqual(v1["key_status"], "rotated_verify_only")

        v2 = self.client.post("/api/v3/security/jwt/verify", json={"token": token_2}).json()
        self.assertTrue(v2["valid"])
        self.assertEqual(v2["key_status"], "active")

        jwks = self.client.get("/.well-known/jwks.json").json()
        self.assertGreaterEqual(len(jwks["keys"]), 2)

    def test_prometheus_metrics_and_opentelemetry_distributed_tracing(self) -> None:
        custom_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        gw_res = self.client.get(
            "/gateway/v2/fx/quotes",
            headers={"traceparent": custom_traceparent},
        )
        self.assertEqual(gw_res.status_code, 200)
        self.assertEqual(gw_res.headers.get("x-trace-id"), "4bf92f3577b34da6a3ce929d0e0e4736")

        trace_res = self.client.get(
            "/api/v3/observability/traces/4bf92f3577b34da6a3ce929d0e0e4736"
        )
        self.assertEqual(trace_res.status_code, 200)
        self.assertEqual(trace_res.json()["parent_span_id"], "00f067aa0ba902b7")
        self.assertEqual(len(trace_res.json()["child_spans"]), 2)

        prom_res = self.client.get("/metrics")
        self.assertEqual(prom_res.status_code, 200)
        self.assertIn("apihub_http_requests_total", prom_res.text)
        self.assertIn("apihub_ai_tokens_total", prom_res.text)

    def test_dx_sdk_generator_webhook_simulator_graphql_and_ddd_events(self) -> None:
        for lang in ("python", "typescript", "go", "curl"):
            sdk = self.client.post(
                "/api/v3/dx/sdk-generate",
                json={"endpoint_path": "/fx/quotes", "method": "GET", "version": "v2", "language": lang},
            )
            self.assertEqual(sdk.status_code, 200)
            self.assertIn("/gateway/v2/fx/quotes", sdk.json()["sdk_code"])

        sim_ok = self.client.post(
            "/api/v3/dx/webhook-simulate",
            json={"event_type": "invoice.paid", "payload": {"amount": 49.0}, "tamper_payload": False},
        ).json()
        self.assertTrue(sim_ok["signature_verified"])

        sim_tampered = self.client.post(
            "/api/v3/dx/webhook-simulate",
            json={"event_type": "invoice.paid", "payload": {"amount": 49.0}, "tamper_payload": True},
        ).json()
        self.assertFalse(sim_tampered["signature_verified"])

        gql = self.client.post(
            "/api/v3/graphql",
            json={"query": "query { _service { sdl } projects { id name } aiModels { id provider } }"},
        )
        self.assertEqual(gql.status_code, 200)
        gql_data = gql.json()["data"]
        self.assertIn("@key", gql_data["_service"]["sdl"])
        self.assertGreaterEqual(len(gql_data["projects"]), 1)
        self.assertGreaterEqual(len(gql_data["aiModels"]), 5)

        ev_stream = self.client.get("/api/v3/architecture/events")
        self.assertEqual(ev_stream.status_code, 200)
        self.assertIn("events", ev_stream.json())


if __name__ == "__main__":
    unittest.main()
