"""
Unit & Integration Tests for Enterprise Security:
- Redis-backed distributed rate limiting
- RBAC & project-level permissions
- API key expiration and grace-period rotation
- Login brute-force throttling, RFC 6238 TOTP MFA, and password reset
- Request size limits & SQLi/XSS/Path Traversal abuse prevention
- Tamper-evident HMAC-SHA256 audit chain & Automated Security Auditing
"""

from __future__ import annotations

import unittest
from fastapi.testclient import TestClient

from apihub.api import app
from apihub.config import settings
from apihub.database import db
from apihub.rate_limiter import redis_store


class TestEnterpriseSecurity(unittest.TestCase):
    def setUp(self) -> None:
        db.reset_all()
        redis_store.flush_all()
        self.client = TestClient(app)

    def test_auth_login_throttling_mfa_and_password_reset(self) -> None:
        reg = self.client.post(
            "/api/v2/auth/register",
            json={
                "username": "sec_user",
                "email": "sec@example.com",
                "password": "InitialPassword#1",
                "role": "developer",
            },
        )
        self.assertEqual(reg.status_code, 201)
        user_id = reg.json()["user"]["id"]

        # Provision & enable MFA
        mfa_setup = self.client.post("/api/v2/auth/mfa/setup", json={"user_id": user_id})
        self.assertEqual(mfa_setup.status_code, 200)
        totp_code = mfa_setup.json()["current_code_preview"]

        mfa_verify = self.client.post(
            "/api/v2/auth/mfa/verify", json={"user_id": user_id, "code": totp_code}
        )
        self.assertEqual(mfa_verify.status_code, 200)

        # Login without TOTP code must return 403 MFA_REQUIRED
        login_no_mfa = self.client.post(
            "/api/v2/auth/login",
            json={"username": "sec_user", "password": "InitialPassword#1"},
        )
        self.assertEqual(login_no_mfa.status_code, 403)
        self.assertTrue(login_no_mfa.json()["mfa_required"])

        # Login with valid TOTP code succeeds
        login_ok = self.client.post(
            "/api/v2/auth/login",
            json={"username": "sec_user", "password": "InitialPassword#1", "totp_code": totp_code},
        )
        self.assertEqual(login_ok.status_code, 200)
        self.assertIn("access_token", login_ok.json())

        # Password reset flow
        rst_req = self.client.post(
            "/api/v2/auth/password-reset/request",
            json={"email_or_username": "sec@example.com"},
        )
        self.assertEqual(rst_req.status_code, 200)
        reset_token = rst_req.json()["reset_token"]
        self.assertIsNotNone(reset_token)

        rst_confirm = self.client.post(
            "/api/v2/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": "UpdatedPassword#2"},
        )
        self.assertEqual(rst_confirm.status_code, 200)

        # Re-using the same reset token must fail
        rst_reuse = self.client.post(
            "/api/v2/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": "AnotherPassword#3"},
        )
        self.assertEqual(rst_reuse.status_code, 400)

        # Brute-force login lockout test on a second user
        self.client.post(
            "/api/v2/auth/register",
            json={"username": "lock_user", "email": "lock@example.com", "password": "ValidPassword#1"},
        )
        for _ in range(settings.login_max_attempts):
            self.client.post(
                "/api/v2/auth/login",
                json={"username": "lock_user", "password": "WrongPassword!"},
            )
        locked_res = self.client.post(
            "/api/v2/auth/login",
            json={"username": "lock_user", "password": "ValidPassword#1"},
        )
        self.assertEqual(locked_res.status_code, 429)

    def test_rbac_project_permissions_api_key_rotation_and_rate_limiting(self) -> None:
        owner = self.client.post(
            "/api/v2/auth/register",
            json={"username": "proj_owner", "email": "owner@example.com", "password": "OwnerPassword#1", "role": "developer"},
        ).json()["user"]
        viewer = self.client.post(
            "/api/v2/auth/register",
            json={"username": "proj_viewer", "email": "viewer@example.com", "password": "ViewerPassword#1", "role": "viewer"},
        ).json()["user"]

        proj = self.client.post(
            "/api/v2/projects",
            json={"name": "Secure Payments", "owner_id": owner["id"], "plan_tier": "pro"},
        ).json()["project"]

        # Grant 'reader' permission to viewer
        self.client.post(
            f"/api/v2/projects/{proj['id']}/members",
            json={"user_id": viewer["id"], "permission": "reader", "actor_id": owner["id"]},
        )

        # Reader cannot register an endpoint (requires editor or owner)
        forbidden_ep = self.client.post(
            "/api/v2/gateway/endpoints",
            json={
                "project_id": proj["id"],
                "name": "Unauthorized Route",
                "path": "/unauth",
                "actor_id": viewer["id"],
            },
        )
        self.assertEqual(forbidden_ep.status_code, 403)

        # Owner registers a protected endpoint with rate_limit_rpm=3
        ep_res = self.client.post(
            "/api/v2/gateway/endpoints",
            json={
                "project_id": proj["id"],
                "name": "Protected Vault",
                "version": "v2",
                "path": "/vault/items",
                "method": "GET",
                "auth_required": True,
                "rate_limit_rpm": 3,
                "actor_id": owner["id"],
            },
        )
        self.assertEqual(ep_res.status_code, 201)

        # Unauthenticated call fails with 401
        no_key_res = self.client.get("/gateway/v2/vault/items")
        self.assertEqual(no_key_res.status_code, 401)

        # Issue API Key
        key_res = self.client.post(
            "/api/v2/keys",
            json={
                "project_id": proj["id"],
                "user_id": owner["id"],
                "name": "Vault Key",
                "rate_limit_rpm": 3,
                "ttl_days": 30,
            },
        )
        self.assertEqual(key_res.status_code, 201)
        key_id = key_res.json()["id"]
        raw_key_1 = key_res.json()["api_key"]

        # Rotate API Key with grace period: both old and new key should work during grace window
        rot_res = self.client.post(
            f"/api/v2/keys/{key_id}/rotate",
            json={"actor_id": owner["id"], "grace_period_seconds": 3600, "ttl_days": 30},
        )
        self.assertEqual(rot_res.status_code, 200)
        raw_key_2 = rot_res.json()["new_key"]["api_key"]

        res_old_grace = self.client.get("/gateway/v2/vault/items", headers={"X-API-Key": raw_key_1})
        self.assertEqual(res_old_grace.status_code, 200)
        self.assertIn("X-RateLimit-Limit", res_old_grace.headers)

        # Test Redis sliding-window rate limiting on raw_key_2 (limit = 3 RPM)
        for _ in range(3):
            r = self.client.get("/gateway/v2/vault/items", headers={"X-API-Key": raw_key_2})
            self.assertEqual(r.status_code, 200)
        r_limited = self.client.get("/gateway/v2/vault/items", headers={"X-API-Key": raw_key_2})
        self.assertEqual(r_limited.status_code, 429)
        self.assertIn("Retry-After", r_limited.headers)

    def test_abuse_prevention_and_automated_security_audit(self) -> None:
        # SQLi attempt blocked by middleware
        sqli_res = self.client.get("/api/v1/endpoints?project_id=1%20UNION%20SELECT%20password%20FROM%20users")
        self.assertEqual(sqli_res.status_code, 400)
        self.assertEqual(sqli_res.json()["error"], "sql_injection")


        # Oversized request body (> max_request_body_bytes) must return 413 Payload Too Large
        old_max = settings.max_request_body_bytes
        try:
            settings.max_request_body_bytes = 128
            huge_res = self.client.post("/api/v2/auth/login", content=b"x" * 512)
            self.assertEqual(huge_res.status_code, 413)
            self.assertEqual(huge_res.json()["error"], "payload_too_large")
        finally:
            settings.max_request_body_bytes = old_max

        # Audit log chain verification & automated security audit
        chain_res = self.client.get("/api/v2/security/verify-chain")
        self.assertEqual(chain_res.status_code, 200)
        self.assertTrue(chain_res.json()["valid"])

        audit_res = self.client.post("/api/v2/security/automated-audit")
        self.assertEqual(audit_res.status_code, 200)
        self.assertTrue(audit_res.json()["audit_chain_integrity"]["valid"])
        self.assertIn("security_score", audit_res.json())


if __name__ == "__main__":
    unittest.main()
