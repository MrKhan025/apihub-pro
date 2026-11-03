"""
Unit & Integration Tests for Dynamic API Gateway, Versioning & Lifecycle,
Request/Response Transformations, Configurable Timeouts, and Webhooks with Retries.
"""

from __future__ import annotations

import unittest
from fastapi.testclient import TestClient

from apihub.api import app
from apihub.database import db
from apihub.marketplace import marketplace_manager
from apihub.rate_limiter import redis_store
from apihub.security import security_manager
from apihub.webhooks import WebhookManager


class TestDynamicGatewayAndWebhooks(unittest.TestCase):
    def setUp(self) -> None:
        db.reset_all()
        redis_store.flush_all()
        self.client = TestClient(app)
        self.owner = security_manager.create_user("gw_admin", "gw@example.com", "StrongPass#123", "admin")
        self.project = marketplace_manager.create_project("Gateway Project", self.owner["id"], plan_tier="pro")

    def test_dynamic_endpoint_registration_transforms_and_caching(self) -> None:
        create_res = self.client.post(
            "/api/v2/gateway/endpoints",
            json={
                "project_id": self.project["id"],
                "name": "User Billing Transform",
                "version": "v2",
                "path": "/billing/summary",
                "method": "POST",
                "lifecycle_state": "active",
                "timeout_ms": 2000,
                "auth_required": False,
                "rate_limit_rpm": 50,
                "response_mode": "echo",
                "request_transform": {
                    "add_headers": {"X-Injected-By-Gateway": "true"},
                    "rename_body_fields": {"old_amount": "amount_cents"},
                    "inject_body_fields": {"region": "APAC"},
                    "remove_body_fields": ["internal_debug"],
                },
                "response_transform": {
                    "add_headers": {"X-Transformed-Response": "v2"},
                    "wrap_envelope": True,
                    "envelope_key": "result",
                },
            },
        )
        self.assertEqual(create_res.status_code, 201)
        ep_id = create_res.json()["endpoint"]["id"]

        exec_res = self.client.post(
            "/gateway/v2/billing/summary",
            json={"old_amount": 4900, "internal_debug": "remove_me"},
        )
        self.assertEqual(exec_res.status_code, 200)
        self.assertEqual(exec_res.headers.get("X-Transformed-Response"), "v2")
        payload = exec_res.json()
        self.assertIn("result", payload)
        echo_body = payload["result"]["echo"]["body"]
        self.assertEqual(echo_body["amount_cents"], 4900)
        self.assertEqual(echo_body["region"], "APAC")
        self.assertNotIn("internal_debug", echo_body)

        # Test Lifecycle transitions: deprecated -> headers, retired -> 410, draft -> 403
        self.client.put(
            f"/api/v2/gateway/endpoints/{ep_id}",
            json={
                "lifecycle_state": "deprecated",
                "deprecation_date": "2026-11-01",
                "sunset_date": "2027-03-01",
            },
        )
        dep_res = self.client.post("/gateway/v2/billing/summary", json={"old_amount": 100})
        self.assertEqual(dep_res.status_code, 200)
        self.assertEqual(dep_res.headers.get("Deprecation"), "2026-11-01")
        self.assertEqual(dep_res.headers.get("Sunset"), "2027-03-01")

        self.client.put(f"/api/v2/gateway/endpoints/{ep_id}", json={"lifecycle_state": "retired"})
        ret_res = self.client.post("/gateway/v2/billing/summary", json={})
        self.assertEqual(ret_res.status_code, 410)

        self.client.put(f"/api/v2/gateway/endpoints/{ep_id}", json={"lifecycle_state": "draft"})
        draft_res = self.client.post("/gateway/v2/billing/summary", json={})
        self.assertEqual(draft_res.status_code, 403)

    def test_configurable_request_timeout_enforcement(self) -> None:
        self.client.post(
            "/api/v2/gateway/endpoints",
            json={
                "project_id": self.project["id"],
                "name": "Slow Upstream Endpoint",
                "version": "v2",
                "path": "/reports/slow",
                "method": "GET",
                "timeout_ms": 100,
                "simulated_latency_ms": 350,
                "auth_required": False,
            },
        )
        res = self.client.get("/gateway/v2/reports/slow")
        self.assertEqual(res.status_code, 504)
        self.assertEqual(res.json()["error"], "Gateway Timeout")

    def test_webhook_management_signing_and_retry_policies(self) -> None:
        wh_res = self.client.post(
            "/api/v2/webhooks",
            json={
                "project_id": self.project["id"],
                "name": "Order Events Hook",
                "target_url": "https://example.internal/webhook",
                "events": ["endpoint.invoked"],
                "secret": "whsec_test_secret_key_12345",
                "max_retries": 3,
                "backoff_strategy": "exponential",
                "initial_delay_ms": 100,
            },
        )
        self.assertEqual(wh_res.status_code, 201)
        wh_id = wh_res.json()["webhook"]["id"]

        # Simulate 2 transient 503 failures before succeeding on attempt 3
        trig_res = self.client.post(
            f"/api/v2/webhooks/{wh_id}/trigger",
            json={
                "event_type": "endpoint.invoked",
                "data": {"order_id": "ord_77"},
                "simulate_failures_before_success": 2,
            },
        )
        self.assertEqual(trig_res.status_code, 200)
        body = trig_res.json()
        self.assertEqual(body["status"], "delivered")
        self.assertEqual(body["attempt_count"], 3)
        self.assertEqual(body["backoff_schedule_ms"], [100, 200])

        # Verify delivery log & HMAC signature
        dlv_res = self.client.get(f"/api/v2/webhooks/{wh_id}/deliveries")
        self.assertEqual(dlv_res.status_code, 200)
        self.assertEqual(dlv_res.json()["count"], 1)
        sig = dlv_res.json()["deliveries"][0]["signature"]
        self.assertTrue(sig.startswith("t="))


if __name__ == "__main__":
    unittest.main()
