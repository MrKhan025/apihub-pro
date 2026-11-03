"""
Unit & Integration Tests for Live Operational Analytics (RPM, Daily Usage,
Latency Percentiles, Error Rates, SVG Charts, CSV/JSON Exports),
API Marketplace & Subscription Plans, and Dashboard UI.
"""

from __future__ import annotations

import unittest
from fastapi.testclient import TestClient

from apihub.api import app
from apihub.database import db
from apihub.rate_limiter import redis_store
from apihub.seed import seed_demo_workspace


class TestAnalyticsMarketplaceAndDashboard(unittest.TestCase):
    def setUp(self) -> None:
        db.reset_all()
        redis_store.flush_all()
        self.client = TestClient(app)
        self.seed_info = seed_demo_workspace()

    def test_analytics_summary_percentiles_svg_and_exports(self) -> None:
        # Execute a few live gateway calls
        for _ in range(3):
            res = self.client.get("/gateway/v2/fx/quotes")
            self.assertEqual(res.status_code, 200)

        summary = self.client.get("/api/v2/analytics/summary").json()
        self.assertGreaterEqual(summary["total_requests"], 13)
        lat = summary["latency_percentiles"]
        self.assertGreater(lat["p50_ms"], 0)
        self.assertGreaterEqual(lat["p95_ms"], lat["p50_ms"])
        self.assertGreaterEqual(lat["p99_ms"], lat["p95_ms"])
        self.assertTrue(len(summary["rpm_series"]) == 15)
        self.assertGreaterEqual(len(summary["daily_usage"]), 1)

        ep_perf = self.client.get("/api/v2/analytics/endpoints").json()
        self.assertGreaterEqual(ep_perf["count"], 2)

        svg_res = self.client.get("/api/v2/analytics/chart.svg")
        self.assertEqual(svg_res.status_code, 200)
        self.assertIn("<svg", svg_res.text)

        csv_res = self.client.get("/api/v2/analytics/export?format=csv")
        self.assertEqual(csv_res.status_code, 200)
        self.assertIn("route,version,method,path,requests", csv_res.text)

        json_res = self.client.get("/api/v2/analytics/export?format=json")
        self.assertEqual(json_res.status_code, 200)
        self.assertEqual(json_res.json()["report_type"], "apihub_pro_analytics_report")

    def test_marketplace_listings_and_subscription_plans(self) -> None:
        plans_res = self.client.get("/api/v2/marketplace/plans")
        self.assertEqual(plans_res.status_code, 200)
        self.assertEqual(plans_res.json()["count"], 3)

        project_id = self.seed_info["project"]["id"]
        user_id = self.seed_info["admin_user"]["id"]

        pub_res = self.client.post(
            "/api/v2/marketplace/listings",
            json={
                "project_id": project_id,
                "title": "Weather Telemetry API",
                "summary": "Global hyper-local weather forecast feed",
                "sample_endpoint_path": "/gateway/v2/weather/forecast",
                "category": "weather",
                "version": "v2",
                "pricing_plan_required": "pro",
                "price_monthly_usd": 49.0,
                "rate_limit_rpm": 600,
                "actor_id": user_id,
            },
        )
        self.assertEqual(pub_res.status_code, 201)
        listing_id = pub_res.json()["listing"]["id"]

        sub_res = self.client.post(
            "/api/v2/marketplace/subscribe",
            json={
                "project_id": project_id,
                "user_id": user_id,
                "plan_id": "enterprise",
                "listing_id": listing_id,
            },
        )
        self.assertEqual(sub_res.status_code, 201)
        self.assertEqual(sub_res.json()["subscription"]["plan"]["id"], "enterprise")

        updated_proj = self.client.get(f"/api/v2/projects/{project_id}").json()
        self.assertEqual(updated_proj["plan_tier"], "enterprise")
        self.assertEqual(updated_proj["rpm_limit"], 5000)

    def test_dashboard_serving(self) -> None:
        dash = self.client.get("/dashboard")
        self.assertEqual(dash.status_code, 200)
        self.assertIn("apihub-pro", dash.text)


if __name__ == "__main__":
    unittest.main()
