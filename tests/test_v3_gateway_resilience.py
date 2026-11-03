"""
Unit & Integration Tests for v3.0 Advanced Gateway Resilience:
- Canary deployments & automatic error-threshold rollback
- Traffic shadowing & payload diff comparison
- Request replay vault
- State-machine circuit breakers (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)
- Dynamic service discovery registry & load-balanced resolution
"""

from __future__ import annotations

import time
import unittest
from fastapi.testclient import TestClient

from apihub.api import app
from apihub.database import db
from apihub.rate_limiter import redis_store
from apihub.seed import seed_demo_workspace


class TestV3GatewayResilience(unittest.TestCase):
    def setUp(self) -> None:
        db.reset_all()
        redis_store.flush_all()
        self.client = TestClient(app)
        self.seed = seed_demo_workspace()
        self.project_id = self.seed["project"]["id"]

        # Register v1 and v2 /orders/status endpoints for canary & shadowing tests
        for ver, body_val in [("v1", {"schema": "v1_legacy"}), ("v2", {"schema": "v2_nextgen"})]:
            self.client.post(
                "/api/v2/gateway/endpoints",
                json={
                    "project_id": self.project_id,
                    "name": f"Orders Status {ver}",
                    "version": ver,
                    "path": "/orders/status",
                    "method": "GET",
                    "auth_required": False,
                    "mock_response_body": body_val,
                },
            )

    def test_canary_deployment_routing_and_auto_rollback(self) -> None:
        cnr = self.client.post(
            "/api/v3/gateway/canary",
            json={
                "project_id": self.project_id,
                "name": "Orders v1-to-v2 Canary",
                "path": "/orders/status",
                "method": "GET",
                "stable_version": "v1",
                "canary_version": "v2",
                "canary_weight_percent": 50,
                "auto_rollback_error_pct": 40.0,
            },
        )
        self.assertEqual(cnr.status_code, 201)
        canary_id = cnr.json()["id"]

        # Force canary via X-Canary: true header and simulate 2 errors to trigger auto-rollback
        r1 = self.client.post(
            f"/api/v3/gateway/canary/{canary_id}/route",
            json={"headers": {"X-Canary": "true"}, "simulate_canary_error": True},
        )
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.json()["routed_to"], "canary")

        r2 = self.client.post(
            f"/api/v3/gateway/canary/{canary_id}/route",
            json={"headers": {"X-Canary": "true"}, "simulate_canary_error": True},
        )
        self.assertEqual(r2.json()["deployment_status"], "rolled_back")

    def test_traffic_shadowing_and_request_replay(self) -> None:
        shadow_res = self.client.post(
            "/api/v3/gateway/shadow",
            json={
                "project_id": self.project_id,
                "path": "/orders/status",
                "method": "GET",
                "primary_version": "v1",
                "shadow_version": "v2",
            },
        )
        self.assertEqual(shadow_res.status_code, 200)
        s_body = shadow_res.json()
        self.assertTrue(s_body["comparison"]["status_match"])
        self.assertFalse(s_body["comparison"]["payload_identical"])

        # Capture & replay request
        cap = self.client.post(
            "/api/v3/gateway/replay/capture",
            json={
                "project_id": self.project_id,
                "version": "v1",
                "method": "GET",
                "path": "/orders/status",
                "original_status": 200,
            },
        )
        self.assertEqual(cap.status_code, 201)
        cap_id = cap.json()["id"]

        rep = self.client.post(f"/api/v3/gateway/replay/{cap_id}/execute?target_version_override=v2")
        self.assertEqual(rep.status_code, 200)
        self.assertEqual(rep.json()["replay_status"], 200)
        self.assertFalse(rep.json()["status_regression_detected"])

    def test_circuit_breaker_state_machine_and_service_discovery(self) -> None:
        self.client.post(
            "/api/v3/gateway/circuit-breakers",
            json={
                "service_name": "payment-upstream",
                "failure_threshold": 2,
                "recovery_timeout_seconds": 10,
                "half_open_max_calls": 2,
            },
        )
        now = time.time()
        # 2 consecutive failures trip CLOSED -> OPEN
        self.client.post(
            "/api/v3/gateway/circuit-breakers/payment-upstream/record",
            json={"call_succeeded": False, "now_override": now},
        )
        cb_open = self.client.post(
            "/api/v3/gateway/circuit-breakers/payment-upstream/record",
            json={"call_succeeded": False, "now_override": now + 1},
        ).json()
        self.assertEqual(cb_open["state"], "OPEN")
        self.assertFalse(cb_open["allowed"])

        # After recovery timeout (now + 15s), transitions OPEN -> HALF_OPEN -> CLOSED after 2 successes
        cb_half = self.client.post(
            "/api/v3/gateway/circuit-breakers/payment-upstream/record",
            json={"call_succeeded": True, "now_override": now + 15},
        ).json()
        self.assertEqual(cb_half["state"], "HALF_OPEN")

        cb_closed = self.client.post(
            "/api/v3/gateway/circuit-breakers/payment-upstream/record",
            json={"call_succeeded": True, "now_override": now + 16},
        ).json()
        self.assertEqual(cb_closed["state"], "CLOSED")
        self.assertTrue(cb_closed["allowed"])

        # Service discovery registration & least_latency resolution
        self.client.post(
            "/api/v3/gateway/discovery/register",
            json={"service_name": "fx-engine", "instance_url": "http://10.0.1.10:8080", "avg_latency_ms": 14.5},
        )
        self.client.post(
            "/api/v3/gateway/discovery/register",
            json={"service_name": "fx-engine", "instance_url": "http://10.0.1.11:8080", "avg_latency_ms": 3.2},
        )
        resolved = self.client.post("/api/v3/gateway/discovery/resolve/fx-engine?strategy=least_latency")
        self.assertEqual(resolved.status_code, 200)
        self.assertEqual(resolved.json()["selected_instance"]["instance_url"], "http://10.0.1.11:8080")


if __name__ == "__main__":
    unittest.main()
