"""
Unit & Integration Tests for Backward Compatibility (v1 routes) and Infrastructure
(PostgreSQL pool configuration, Alembic migrations, and CLI commands).
"""

from __future__ import annotations

import unittest
from fastapi.testclient import TestClient

from apihub.api import app
from apihub.config import Settings
from apihub.database import db
from apihub.rate_limiter import redis_store
from apihub.seed import seed_demo_workspace


class TestBackwardCompatAndInfra(unittest.TestCase):
    def setUp(self) -> None:
        db.reset_all()
        redis_store.flush_all()
        self.client = TestClient(app)

    def test_v1_backward_compatible_routes(self) -> None:
        seed_demo_workspace()
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "healthy")
        self.assertEqual(health.json()["version"], "2.0.0")

        v1_status = self.client.get("/api/v1/status")
        self.assertEqual(v1_status.status_code, 200)
        self.assertTrue(v1_status.json()["backward_compatible"])

        v1_eps = self.client.get("/api/v1/endpoints")
        self.assertEqual(v1_eps.status_code, 200)
        self.assertGreaterEqual(v1_eps.json()["count"], 3)

        v1_projs = self.client.get("/api/v1/projects")
        self.assertEqual(v1_projs.status_code, 200)
        self.assertGreaterEqual(v1_projs.json()["count"], 1)

        v1_keys = self.client.get("/api/v1/keys")
        self.assertEqual(v1_keys.status_code, 200)
        self.assertGreaterEqual(v1_keys.json()["count"], 1)

    def test_alembic_migrations_and_postgres_pool_config(self) -> None:
        mig_res = self.client.post("/api/v2/infra/migrate?target_revision=0001_v1_baseline")
        self.assertEqual(mig_res.status_code, 200)
        self.assertEqual(mig_res.json()["current_revision"], "0001_v1_baseline")

        mig_head = self.client.post("/api/v2/infra/migrate?target_revision=head")
        self.assertEqual(mig_head.status_code, 200)
        self.assertEqual(mig_head.json()["current_revision"], "0002_v2_advanced_engine")

        pg_settings = Settings(
            database_url="postgresql+psycopg2://user:pass@db.internal:5432/apihub_pro",
            db_pool_size=25,
            db_max_overflow=15,
            db_pool_pre_ping=True,
            db_ssl_mode="require",
        )
        self.assertTrue(pg_settings.is_postgres)
        pool_kwargs = pg_settings.get_sqlalchemy_engine_kwargs()
        self.assertEqual(pool_kwargs["pool_size"], 25)
        self.assertEqual(pool_kwargs["max_overflow"], 15)
        self.assertEqual(pool_kwargs["pool_pre_ping"], True)

        infra = self.client.get("/api/v2/infra/status")
        self.assertEqual(infra.status_code, 200)
        self.assertEqual(infra.json()["database"]["current_revision"], "0002_v2_advanced_engine")


if __name__ == "__main__":
    unittest.main()
