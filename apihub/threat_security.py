"""
Advanced Enterprise Threat Intelligence, Device Fingerprinting, Risk Scoring & JWKS Key Rotation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional

from apihub.database import db
from apihub.rate_limiter import redis_store
from apihub.security import AuditLogger


KNOWN_THREAT_IPS = {"198.51.100.66", "203.0.113.99", "192.0.2.250"}
SUSPICIOUS_USER_AGENTS = ("sqlmap", "nikto", "masscan", "zgrab", "nuclei", "hydra")


class ThreatAndIdentityEngine:
    """Computes device fingerprints, evaluates request risk scores, detects API abuse, and rotates JWT keys."""

    @staticmethod
    def compute_device_fingerprint(
        user_agent: str,
        accept_language: str = "en-US",
        sec_ch_ua: str = "",
        client_ip: str = "127.0.0.1",
    ) -> str:
        ip_subnet = ".".join(client_ip.split(".")[:3]) if "." in client_ip else client_ip
        canonical = f"{user_agent.strip().lower()}|{accept_language.strip().lower()}|{sec_ch_ua.strip()}|{ip_subnet}"
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
        return f"fp_{digest}"

    @classmethod
    def evaluate_request_risk(
        cls,
        client_ip: str,
        path: str,
        method: str = "GET",
        user_agent: str = "Mozilla/5.0",
        accept_language: str = "en-US",
        sec_ch_ua: str = "",
        known_fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        fingerprint = cls.compute_device_fingerprint(
            user_agent=user_agent,
            accept_language=accept_language,
            sec_ch_ua=sec_ch_ua,
            client_ip=client_ip,
        )
        risk_score = 0
        reasons: List[str] = []

        if client_ip in KNOWN_THREAT_IPS:
            risk_score += 65
            reasons.append("threat_intel_blocklisted_ip")

        ua_lower = user_agent.lower()
        if any(sig in ua_lower for sig in SUSPICIOUS_USER_AGENTS):
            risk_score += 55
            reasons.append("malicious_scanner_user_agent")

        if known_fingerprint and known_fingerprint != fingerprint:
            risk_score += 30
            reasons.append("device_fingerprint_drift")

        vel = redis_store.sliding_window_check(f"abuse_vel:{client_ip}", limit=40, window_seconds=60)
        if not vel["allowed"]:
            risk_score += 40
            reasons.append("high_velocity_api_abuse")

        if any(seg in path for seg in ("/auth/", "/keys", "/security/", "/billing/")):
            risk_score += 10
            reasons.append("sensitive_control_plane_route")

        risk_score = min(100, risk_score)
        if risk_score >= 75:
            risk_level = "critical"
            action = "block"
        elif risk_score >= 40:
            risk_level = "high"
            action = "step_up_mfa"
        elif risk_score >= 20:
            risk_level = "medium"
            action = "allow_monitored"
        else:
            risk_level = "low"
            action = "allow"

        evt_id = f"thr_{uuid.uuid4().hex[:12]}"
        now = time.time()
        db.execute(
            """
            INSERT INTO threat_intel_events
            (id, client_ip, device_fingerprint, risk_score, risk_level, action_taken, reasons, path, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evt_id,
                client_ip,
                fingerprint,
                int(risk_score),
                risk_level,
                action,
                json.dumps(reasons),
                path,
                now,
            ),
        )
        return {
            "event_id": evt_id,
            "client_ip": client_ip,
            "device_fingerprint": fingerprint,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "action": action,
            "reasons": reasons,
            "evaluated_at": now,
        }

    @staticmethod
    def list_threat_events(limit: int = 50) -> List[Dict[str, Any]]:
        rows = db.fetch_all(
            "SELECT * FROM threat_intel_events ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        return [{**dict(r), "reasons": json.loads(r["reasons"] or "[]")} for r in rows]

    @classmethod
    def ensure_active_jwt_key(cls) -> Dict[str, Any]:
        row = db.fetch_one(
            "SELECT * FROM jwt_signing_keys WHERE status = 'active' ORDER BY created_at DESC LIMIT 1"
        )
        if not row:
            cls.rotate_jwt_signing_key()
            row = db.fetch_one("SELECT * FROM jwt_signing_keys WHERE status = 'active' ORDER BY created_at DESC LIMIT 1")
        return dict(row) if row else {}

    @classmethod
    def rotate_jwt_signing_key(cls, grace_period_seconds: int = 86400) -> Dict[str, Any]:
        now = time.time()
        db.execute(
            """
            UPDATE jwt_signing_keys
            SET status = 'rotated_verify_only', expires_at = ?
            WHERE status = 'active'
            """,
            (now + grace_period_seconds,),
        )
        kid = f"kid_{uuid.uuid4().hex[:12]}"
        secret_material = secrets.token_urlsafe(32)
        pub_fingerprint = hashlib.sha256(secret_material.encode("utf-8")).digest()
        jwk = {
            "kty": "oct",
            "kid": kid,
            "use": "sig",
            "alg": "HS256",
            "x5t#S256": base64.urlsafe_b64encode(pub_fingerprint).decode("ascii").rstrip("="),
        }
        db.execute(
            """
            INSERT INTO jwt_signing_keys (kid, algorithm, secret_material, public_jwk, status, created_at, expires_at)
            VALUES (?, 'HS256', ?, ?, 'active', ?, ?)
            """,
            (kid, secret_material, json.dumps(jwk), now, now + 90 * 86400),
        )
        AuditLogger.log_event(
            event_type="security.jwt_key_rotated",
            description=f"Rotated active JWT signing key to {kid}",
            metadata={"kid": kid, "grace_period_seconds": grace_period_seconds},
        )
        return {
            "kid": kid,
            "algorithm": "HS256",
            "status": "active",
            "public_jwk": jwk,
            "created_at": now,
        }

    @classmethod
    def get_jwks(cls) -> Dict[str, Any]:
        cls.ensure_active_jwt_key()
        now = time.time()
        rows = db.fetch_all(
            "SELECT * FROM jwt_signing_keys WHERE status IN ('active', 'rotated_verify_only') AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC",
            (now,),
        )
        return {
            "keys": [
                {**json.loads(r["public_jwk"]), "status": r["status"]}
                for r in rows
            ]
        }

    @classmethod
    def issue_jwt(cls, subject: str, claims: Optional[Dict[str, Any]] = None, ttl_seconds: int = 3600) -> Dict[str, Any]:
        active = cls.ensure_active_jwt_key()
        kid = active["kid"]
        secret = active["secret_material"]
        now = int(time.time())
        header = {"alg": "HS256", "typ": "JWT", "kid": kid}
        payload = {
            "sub": subject,
            "iss": "apihub-pro-v3",
            "iat": now,
            "exp": now + ttl_seconds,
            **(claims or {}),
        }
        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode("ascii").rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
        signing_input = f"{h_b64}.{p_b64}"
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
        ).decode("ascii").rstrip("=")
        return {
            "token": f"{signing_input}.{sig}",
            "kid": kid,
            "expires_at": now + ttl_seconds,
        }

    @classmethod
    def verify_jwt(cls, token: str) -> Dict[str, Any]:
        try:
            h_b64, p_b64, sig_b64 = token.split(".")
            header = json.loads(
                base64.urlsafe_b64decode(h_b64 + "=" * ((4 - len(h_b64) % 4) % 4)).decode("utf-8")
            )
            kid = header.get("kid")
            row = db.fetch_one("SELECT * FROM jwt_signing_keys WHERE kid = ?", (kid,))
            if not row or row["status"] == "revoked":
                return {"valid": False, "reason": "unknown_or_revoked_kid"}
            if row["expires_at"] and float(row["expires_at"]) < time.time():
                return {"valid": False, "reason": "signing_key_expired"}

            signing_input = f"{h_b64}.{p_b64}"
            expected_sig = base64.urlsafe_b64encode(
                hmac.new(
                    row["secret_material"].encode("utf-8"),
                    signing_input.encode("utf-8"),
                    hashlib.sha256,
                ).digest()
            ).decode("ascii").rstrip("=")
            if not hmac.compare_digest(sig_b64, expected_sig):
                return {"valid": False, "reason": "invalid_signature"}

            payload = json.loads(
                base64.urlsafe_b64decode(p_b64 + "=" * ((4 - len(p_b64) % 4) % 4)).decode("utf-8")
            )
            if payload.get("exp", 0) < time.time():
                return {"valid": False, "reason": "token_expired"}
            return {
                "valid": True,
                "kid": kid,
                "key_status": row["status"],
                "claims": payload,
            }
        except Exception as exc:
            return {"valid": False, "reason": str(exc)}


threat_security_engine = ThreatAndIdentityEngine()
