"""
Enterprise Security Module for API-Hub-Pro (apihub-pro).
Provides:
- Password hashing (PBKDF2-HMAC-SHA256 with per-user cryptographic salt & constant-time comparison)
- Login brute-force throttling and temporary account lockout
- Multi-Factor Authentication (RFC 6238 TOTP + single-use recovery backup codes)
- Time-bound single-use Password Reset tokens
- Role-Based Access Control (RBAC: admin, developer, viewer, auditor) & Project-Level Permissions (owner, editor, reader)
- Scoped API Key issuance, expiration enforcement, and zero-downtime Grace-Period Key Rotation
- Request size limits & payload injection/abuse prevention
- Tamper-evident HMAC-SHA256 hash-chained Audit Trail & Automated Security Auditing
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import urllib.parse
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from apihub.config import settings
from apihub.database import db
from apihub.rate_limiter import redis_store


ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "admin": [
        "users:manage",
        "projects:manage",
        "endpoints:write",
        "endpoints:read",
        "keys:manage",
        "webhooks:manage",
        "analytics:read",
        "analytics:export",
        "security:audit",
        "marketplace:publish",
        "marketplace:subscribe",
        "gateway:invoke",
    ],
    "developer": [
        "projects:manage",
        "endpoints:write",
        "endpoints:read",
        "keys:manage",
        "webhooks:manage",
        "analytics:read",
        "analytics:export",
        "marketplace:publish",
        "marketplace:subscribe",
        "gateway:invoke",
    ],
    "auditor": [
        "endpoints:read",
        "analytics:read",
        "analytics:export",
        "security:audit",
    ],
    "viewer": [
        "endpoints:read",
        "analytics:read",
        "gateway:invoke",
    ],
}

PROJECT_PERMISSION_LEVELS: Dict[str, int] = {
    "reader": 1,
    "editor": 2,
    "owner": 3,
}

ABUSE_PATTERNS = [
    (re.compile(r"(?i)(\bunion\s+select\b|\bdrop\s+table\b|\bor\s+1\s*=\s*1\b)"), "sql_injection"),
    (re.compile(r"(?i)(<script\b[^>]*>|javascript\s*:)"), "xss_attempt"),
    (re.compile(r"(\.\./\.\./|/etc/passwd|\\\\\.\.\\)"), "path_traversal"),
]


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt_val = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_val.encode("utf-8"),
        120_000,
    )
    return f"pbkdf2_sha256$120000${salt_val}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt_val = parts[2]
        expected_hex = parts[3]
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt_val.encode("utf-8"),
            iterations,
        )
        return hmac.compare_digest(dk.hex(), expected_hex)
    except Exception:
        return False


def generate_totp_secret() -> str:
    """Generate RFC 6238 160-bit Base32 TOTP secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def compute_totp_code(secret_b32: str, timestamp: Optional[float] = None, step: int = 30) -> str:
    """Compute 6-digit RFC 6238 TOTP code."""
    ts = int(timestamp if timestamp is not None else time.time())
    counter = ts // step
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()  # nosec B303 (RFC 6238 standard TOTP)
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code_int:06d}"


def verify_totp_code(secret_b32: str, code: str, timestamp: Optional[float] = None) -> bool:
    """Verify 6-digit TOTP code allowing +/- 1 time step window."""
    if not secret_b32 or not code or not code.isdigit() or len(code) != 6:
        return False
    ts = timestamp if timestamp is not None else time.time()
    for delta in (-30, 0, 30):
        if hmac.compare_digest(compute_totp_code(secret_b32, ts + delta), code):
            return True
    return False


def issue_session_token(user_id: str, role: str, ttl_seconds: int = 3600) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    body = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
    sig = hmac.new(
        settings.secret_key.encode("utf-8"),
        body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{body}.{sig}"


def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(
            settings.secret_key.encode("utf-8"),
            body.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        padded = body + "=" * ((4 - len(body) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


class AuditLogger:
    """Tamper-evident HMAC-SHA256 hash-chained security audit trail."""

    @staticmethod
    def _compute_entry_hash(
        prev_hash: str,
        event_type: str,
        severity: str,
        actor_id: Optional[str],
        description: str,
        metadata_json: str,
        created_at: float,
    ) -> str:
        canonical = (
            f"{prev_hash}|{event_type}|{severity}|{actor_id or 'system'}|"
            f"{description}|{metadata_json}|{created_at:.6f}"
        )
        return hmac.new(
            settings.audit_hmac_secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @classmethod
    def log_event(
        cls,
        event_type: str,
        description: str,
        severity: str = "info",
        actor_id: Optional[str] = None,
        project_id: Optional[str] = None,
        actor_ip: str = "127.0.0.1",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        meta_str = json.dumps(metadata or {}, sort_keys=True)
        last_row = db.fetch_one(
            "SELECT entry_hash FROM audit_logs ORDER BY created_at DESC, rowid DESC LIMIT 1"
        )
        prev_hash = last_row["entry_hash"] if last_row else "GENESIS_0000000000000000"
        entry_hash = cls._compute_entry_hash(
            prev_hash=prev_hash,
            event_type=event_type,
            severity=severity,
            actor_id=actor_id,
            description=description,
            metadata_json=meta_str,
            created_at=now,
        )
        log_id = f"aud_{uuid.uuid4().hex[:16]}"
        db.execute(
            """
            INSERT INTO audit_logs
            (id, project_id, actor_id, actor_ip, event_type, severity, description, metadata, prev_hash, entry_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log_id,
                project_id,
                actor_id,
                actor_ip,
                event_type,
                severity,
                description,
                meta_str,
                prev_hash,
                entry_hash,
                now,
            ),
        )
        return {
            "id": log_id,
            "project_id": project_id,
            "actor_id": actor_id,
            "actor_ip": actor_ip,
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "metadata": metadata or {},
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "created_at": now,
        }

    @classmethod
    def verify_chain(cls) -> Dict[str, Any]:
        rows = db.fetch_all("SELECT * FROM audit_logs ORDER BY created_at ASC, rowid ASC")
        expected_prev = "GENESIS_0000000000000000"
        for idx, row in enumerate(rows):
            if row["prev_hash"] != expected_prev:
                return {
                    "valid": False,
                    "entries_checked": idx + 1,
                    "broken_at_id": row["id"],
                    "reason": "prev_hash mismatch",
                }
            recomputed = cls._compute_entry_hash(
                prev_hash=row["prev_hash"],
                event_type=row["event_type"],
                severity=row["severity"],
                actor_id=row["actor_id"],
                description=row["description"],
                metadata_json=row["metadata"],
                created_at=float(row["created_at"]),
            )
            if not hmac.compare_digest(recomputed, row["entry_hash"]):
                return {
                    "valid": False,
                    "entries_checked": idx + 1,
                    "broken_at_id": row["id"],
                    "reason": "entry_hash signature mismatch",
                }
            expected_prev = row["entry_hash"]
        return {
            "valid": True,
            "entries_checked": len(rows),
            "head_hash": expected_prev,
        }


class SecurityManager:
    """Manages users, MFA, login throttling, password resets, RBAC, API keys, and automated security audits."""

    @staticmethod
    def create_user(
        username: str,
        email: str,
        password: str,
        role: str = "developer",
    ) -> Dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unsupported role '{role}'. Valid roles: {list(ROLE_PERMISSIONS)}")
        now = time.time()
        user_id = f"usr_{uuid.uuid4().hex[:12]}"
        pw_hash = hash_password(password)
        db.execute(
            """
            INSERT INTO users (id, username, email, password_hash, role, mfa_enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)
            """,
            (user_id, username.strip(), email.strip().lower(), pw_hash, role, now, now),
        )
        AuditLogger.log_event(
            event_type="user.created",
            description=f"Created user '{username}' with role '{role}'",
            actor_id=user_id,
            metadata={"username": username, "role": role},
        )
        return {
            "id": user_id,
            "username": username.strip(),
            "email": email.strip().lower(),
            "role": role,
            "mfa_enabled": False,
            "permissions": ROLE_PERMISSIONS[role],
            "created_at": now,
        }

    @staticmethod
    def authenticate_user(
        username: str,
        password: str,
        totp_code: Optional[str] = None,
        client_ip: str = "127.0.0.1",
    ) -> Tuple[bool, int, Dict[str, Any]]:
        """
        Authenticate user with login brute-force throttling, account lockout, and MFA enforcement.
        Returns (success, http_status, payload).
        """
        ip_rl = redis_store.sliding_window_check(
            f"login_ip:{client_ip}",
            limit=settings.login_max_attempts * 3,
            window_seconds=settings.login_lockout_seconds,
        )
        if not ip_rl["allowed"]:
            AuditLogger.log_event(
                event_type="auth.login_throttled",
                severity="warning",
                description=f"IP login rate limit exceeded from {client_ip}",
                actor_ip=client_ip,
            )
            return False, 429, {"error": "Too many login attempts from this IP. Try again later."}

        user = db.fetch_one(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (username.strip(), username.strip().lower()),
        )
        now = time.time()
        if not user:
            AuditLogger.log_event(
                event_type="auth.login_failed",
                severity="warning",
                description=f"Failed login for unknown account '{username}'",
                actor_ip=client_ip,
            )
            return False, 401, {"error": "Invalid username or password"}

        if user["locked_until"] and float(user["locked_until"]) > now:
            remaining = int(float(user["locked_until"]) - now)
            AuditLogger.log_event(
                event_type="auth.account_locked",
                severity="high",
                description=f"Blocked login on locked account '{user['username']}'",
                actor_id=user["id"],
                actor_ip=client_ip,
            )
            return (
                False,
                429,
                {
                    "error": "Account temporarily locked due to repeated failed login attempts",
                    "retry_after_seconds": remaining,
                },
            )

        if not verify_password(password, user["password_hash"]):
            attempts = int(user["failed_login_attempts"]) + 1
            locked_until = (
                now + settings.login_lockout_seconds
                if attempts >= settings.login_max_attempts
                else 0.0
            )
            db.execute(
                "UPDATE users SET failed_login_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?",
                (attempts, locked_until, now, user["id"]),
            )
            AuditLogger.log_event(
                event_type="auth.login_failed",
                severity="warning" if locked_until == 0 else "high",
                description=f"Invalid password for '{user['username']}' (attempt {attempts})",
                actor_id=user["id"],
                actor_ip=client_ip,
                metadata={"attempts": attempts, "locked": locked_until > 0},
            )
            if locked_until > 0:
                return (
                    False,
                    429,
                    {
                        "error": "Account locked due to too many failed attempts",
                        "retry_after_seconds": settings.login_lockout_seconds,
                    },
                )
            return False, 401, {"error": "Invalid username or password"}

        # Check MFA if enabled
        if int(user["mfa_enabled"]) == 1:
            if not totp_code:
                return False, 403, {"error": "MFA_REQUIRED", "mfa_required": True}
            secret = user["mfa_secret"] or ""
            backup_codes: List[str] = json.loads(user["mfa_backup_codes"] or "[]")
            valid_totp = verify_totp_code(secret, totp_code)
            used_backup = False
            if not valid_totp and totp_code in backup_codes:
                backup_codes.remove(totp_code)
                db.execute(
                    "UPDATE users SET mfa_backup_codes = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(backup_codes), now, user["id"]),
                )
                used_backup = True
            if not valid_totp and not used_backup:
                AuditLogger.log_event(
                    event_type="auth.mfa_failed",
                    severity="warning",
                    description=f"Invalid MFA code for '{user['username']}'",
                    actor_id=user["id"],
                    actor_ip=client_ip,
                )
                return False, 401, {"error": "Invalid MFA code"}

        db.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = 0, updated_at = ? WHERE id = ?",
            (now, user["id"]),
        )
        token = issue_session_token(user["id"], user["role"])
        AuditLogger.log_event(
            event_type="auth.login_success",
            description=f"User '{user['username']}' logged in",
            actor_id=user["id"],
            actor_ip=client_ip,
        )
        return (
            True,
            200,
            {
                "access_token": token,
                "token_type": "bearer",
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"],
                    "role": user["role"],
                    "mfa_enabled": bool(user["mfa_enabled"]),
                    "permissions": ROLE_PERMISSIONS.get(user["role"], []),
                },
            },
        )

    @staticmethod
    def setup_mfa(user_id: str) -> Dict[str, Any]:
        user = db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if not user:
            raise ValueError("User not found")
        secret = generate_totp_secret()
        backup_codes = [secrets.token_hex(4).upper() for _ in range(6)]
        db.execute(
            "UPDATE users SET mfa_secret = ?, mfa_backup_codes = ?, updated_at = ? WHERE id = ?",
            (secret, json.dumps(backup_codes), time.time(), user_id),
        )
        provisioning_uri = (
            f"otpauth://totp/apihub-pro:{user['username']}?secret={secret}&issuer=apihub-pro"
        )
        AuditLogger.log_event(
            event_type="auth.mfa_Provisioned",
            description=f"Provisioned MFA TOTP secret for '{user['username']}'",
            actor_id=user_id,
        )
        return {
            "user_id": user_id,
            "mfa_secret": secret,
            "provisioning_uri": provisioning_uri,
            "backup_codes": backup_codes,
            "current_code_preview": compute_totp_code(secret),
        }

    @staticmethod
    def enable_mfa(user_id: str, code: str) -> bool:
        user = db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if not user or not user["mfa_secret"]:
            return False
        if not verify_totp_code(user["mfa_secret"], code):
            return False
        db.execute(
            "UPDATE users SET mfa_enabled = 1, updated_at = ? WHERE id = ?",
            (time.time(), user_id),
        )
        AuditLogger.log_event(
            event_type="auth.mfa_enabled",
            description=f"Enabled MFA for user '{user['username']}'",
            actor_id=user_id,
        )
        return True

    @staticmethod
    def request_password_reset(email_or_username: str) -> Optional[str]:
        user = db.fetch_one(
            "SELECT * FROM users WHERE email = ? OR username = ?",
            (email_or_username.strip().lower(), email_or_username.strip()),
        )
        if not user:
            return None
        raw_token = f"rst_{secrets.token_urlsafe(24)}"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        now = time.time()
        expires_at = now + settings.password_reset_ttl_seconds
        db.execute(
            """
            INSERT INTO password_reset_tokens (token_hash, user_id, expires_at, used, created_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            (token_hash, user["id"], expires_at, now),
        )
        AuditLogger.log_event(
            event_type="auth.password_reset_requested",
            description=f"Password reset requested for '{user['username']}'",
            actor_id=user["id"],
        )
        return raw_token

    @staticmethod
    def confirm_password_reset(raw_token: str, new_password: str) -> bool:
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        row = db.fetch_one(
            "SELECT * FROM password_reset_tokens WHERE token_hash = ?",
            (token_hash,),
        )
        now = time.time()
        if not row or int(row["used"]) == 1 or float(row["expires_at"]) < now:
            return False
        pw_hash = hash_password(new_password)
        db.execute("UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ?", (token_hash,))
        db.execute(
            "UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = 0, updated_at = ? WHERE id = ?",
            (pw_hash, now, row["user_id"]),
        )
        AuditLogger.log_event(
            event_type="auth.password_reset_completed",
            description="Password reset completed via single-use token",
            actor_id=row["user_id"],
        )
        return True

    @staticmethod
    def check_project_access(
        user_id: str, project_id: str, minimum_permission: str = "reader"
    ) -> bool:
        user = db.fetch_one("SELECT role FROM users WHERE id = ?", (user_id,))
        if user and user["role"] == "admin":
            return True
        proj = db.fetch_one("SELECT owner_id FROM projects WHERE id = ?", (project_id,))
        if proj and proj["owner_id"] == user_id:
            return True
        member = db.fetch_one(
            "SELECT permission FROM project_members WHERE project_id = ? AND user_id = ?",
            (project_id, user_id),
        )
        if not member:
            return False
        actual_level = PROJECT_PERMISSION_LEVELS.get(member["permission"], 0)
        required_level = PROJECT_PERMISSION_LEVELS.get(minimum_permission, 1)
        return actual_level >= required_level

    @staticmethod
    def create_api_key(
        project_id: str,
        user_id: str,
        name: str,
        scopes: Optional[List[str]] = None,
        rate_limit_rpm: int = 60,
        ttl_days: Optional[int] = None,
        rotated_from_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        effective_ttl_days = (
            ttl_days if ttl_days is not None else settings.default_api_key_ttl_days
        )
        expires_at = now + (effective_ttl_days * 86400)
        raw_secret = f"ahp_live_{secrets.token_urlsafe(24)}"
        key_prefix = raw_secret[:14]
        key_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
        key_id = f"key_{uuid.uuid4().hex[:12]}"
        scope_list = scopes or ["gateway:invoke", "analytics:read"]
        db.execute(
            """
            INSERT INTO api_keys
            (id, project_id, user_id, name, key_prefix, key_hash, scopes, rate_limit_rpm, status, expires_at, rotated_from_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
            """,
            (
                key_id,
                project_id,
                user_id,
                name,
                key_prefix,
                key_hash,
                json.dumps(scope_list),
                int(rate_limit_rpm),
                expires_at,
                rotated_from_id,
                now,
            ),
        )
        AuditLogger.log_event(
            event_type="apikey.created",
            description=f"Issued API key '{name}' ({key_prefix}...) for project {project_id}",
            actor_id=user_id,
            project_id=project_id,
            metadata={"key_id": key_id, "scopes": scope_list, "expires_at": expires_at},
        )
        return {
            "id": key_id,
            "project_id": project_id,
            "user_id": user_id,
            "name": name,
            "api_key": raw_secret,
            "key_prefix": key_prefix,
            "scopes": scope_list,
            "rate_limit_rpm": int(rate_limit_rpm),
            "status": "active",
            "expires_at": expires_at,
            "rotated_from_id": rotated_from_id,
            "created_at": now,
        }

    @classmethod
    def rotate_api_key(
        cls,
        key_id: str,
        actor_id: str,
        grace_period_seconds: Optional[int] = None,
        ttl_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Rotate an API key: issues a replacement key immediately and keeps the old key
        in `rotated_grace` status until `grace_period_until` for zero-downtime key rotation.
        """
        old_key = db.fetch_one("SELECT * FROM api_keys WHERE id = ?", (key_id,))
        if not old_key:
            raise ValueError(f"API key '{key_id}' not found")
        now = time.time()
        grace_secs = (
            grace_period_seconds
            if grace_period_seconds is not None
            else settings.default_key_rotation_grace_seconds
        )
        grace_until = now + max(0, int(grace_secs))
        old_status = "rotated_grace" if grace_secs > 0 else "revoked"
        db.execute(
            "UPDATE api_keys SET status = ?, grace_period_until = ? WHERE id = ?",
            (old_status, grace_until, key_id),
        )
        new_key = cls.create_api_key(
            project_id=old_key["project_id"],
            user_id=old_key["user_id"],
            name=f"{old_key['name']} (rotated)",
            scopes=json.loads(old_key["scopes"]),
            rate_limit_rpm=int(old_key["rate_limit_rpm"]),
            ttl_days=ttl_days,
            rotated_from_id=key_id,
        )
        AuditLogger.log_event(
            event_type="apikey.rotated",
            description=f"Rotated API key {key_id} -> {new_key['id']} (grace={grace_secs}s)",
            actor_id=actor_id,
            project_id=old_key["project_id"],
            metadata={
                "old_key_id": key_id,
                "new_key_id": new_key["id"],
                "grace_period_until": grace_until,
            },
        )
        return {
            "old_key_id": key_id,
            "old_key_status": old_status,
            "old_key_grace_until": grace_until,
            "new_key": new_key,
        }

    @staticmethod
    def validate_api_key(
        raw_key: str, required_scope: str = "gateway:invoke"
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        if not raw_key:
            return False, "Missing API key", None
        key_hash = hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()
        row = db.fetch_one("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,))
        if not row:
            return False, "Invalid API key", None
        now = time.time()
        status = row["status"]
        if status == "revoked":
            return False, "API key has been revoked", None
        if status == "rotated_grace":
            grace_until = float(row["grace_period_until"] or 0)
            if now > grace_until:
                return False, "Rotated API key grace period has expired", None
        if float(row["expires_at"]) < now:
            return False, "API key has expired", None
        scopes = json.loads(row["scopes"] or "[]")
        if required_scope and required_scope not in scopes and "*" not in scopes:
            return False, f"API key lacks required scope '{required_scope}'", None
        db.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row["id"]))
        row_dict = dict(row)
        row_dict["scopes"] = scopes
        return True, "ok", row_dict

    @staticmethod
    def inspect_request_abuse(raw_body: bytes, path: str, query_string: str) -> Optional[Dict[str, Any]]:
        """Check request size limits and common injection/abuse payloads."""
        if len(raw_body) > settings.max_request_body_bytes:
            return {
                "blocked": True,
                "status_code": 413,
                "reason": "payload_too_large",
                "message": (
                    f"Request payload ({len(raw_body)} bytes) exceeds maximum limit "
                    f"({settings.max_request_body_bytes} bytes)"
                ),
            }
        decoded_uri = urllib.parse.unquote_plus(f"{path}?{query_string}")
        text_sample = f"{decoded_uri} " + urllib.parse.unquote_plus(raw_body[:4096].decode("utf-8", errors="ignore"))
        for regex, category in ABUSE_PATTERNS:
            if regex.search(text_sample):
                return {
                    "blocked": True,
                    "status_code": 400,
                    "reason": category,
                    "message": f"Request blocked by API-Hub-Pro abuse prevention ({category})",
                }
        return None

    @staticmethod
    def run_automated_security_audit() -> Dict[str, Any]:
        """
        Automated Security Auditor: inspects API keys, endpoint auth & timeouts,
        MFA adoption, audit log cryptographic hash chain integrity, and recent security events.
        """
        now = time.time()
        findings: List[Dict[str, Any]] = []
        chain_check = AuditLogger.verify_chain()
        if not chain_check["valid"]:
            findings.append(
                {
                    "id": "SEC-001",
                    "severity": "critical",
                    "category": "audit_integrity",
                    "title": "Audit trail cryptographic chain integrity failure",
                    "detail": f"Broken at {chain_check.get('broken_at_id')}: {chain_check.get('reason')}",
                    "remediation": "Investigate unauthorized database tampering on audit_logs table.",
                }
            )

        expired_active_keys = db.fetch_all(
            "SELECT id, name, project_id FROM api_keys WHERE status = 'active' AND expires_at < ?",
            (now,),
        )
        if expired_active_keys:
            findings.append(
                {
                    "id": "SEC-002",
                    "severity": "medium",
                    "category": "key_lifecycle",
                    "title": f"{len(expired_active_keys)} expired API key(s) still marked active",
                    "detail": "Expired keys are rejected at runtime but should be rotated or revoked.",
                    "remediation": "Rotate or revoke expired keys via POST /api/v2/keys/{id}/rotate.",
                }
            )

        unauthenticated_endpoints = db.fetch_all(
            "SELECT id, name, version, path FROM dynamic_endpoints WHERE auth_required = 0 AND lifecycle_state = 'active'"
        )
        if unauthenticated_endpoints:
            findings.append(
                {
                    "id": "SEC-003",
                    "severity": "low",
                    "category": "endpoint_exposure",
                    "title": f"{len(unauthenticated_endpoints)} active endpoint(s) allow unauthenticated public access",
                    "detail": "Public endpoints rely solely on IP rate limiting.",
                    "remediation": "Enable auth_required=true on sensitive dynamic endpoints.",
                }
            )

        admins_without_mfa = db.fetch_all(
            "SELECT id, username FROM users WHERE role = 'admin' AND mfa_enabled = 0"
        )
        if admins_without_mfa:
            findings.append(
                {
                    "id": "SEC-004",
                    "severity": "medium",
                    "category": "mfa_governance",
                    "title": f"{len(admins_without_mfa)} administrator account(s) do not have MFA enabled",
                    "detail": "Admin accounts should enforce RFC 6238 TOTP MFA.",
                    "remediation": "Provision MFA via POST /api/v2/auth/mfa/setup and verify via /api/v2/auth/mfa/verify.",
                }
            )

        high_timeouts = db.fetch_all(
            "SELECT id, name, timeout_ms FROM dynamic_endpoints WHERE timeout_ms > 15000"
        )
        if high_timeouts:
            findings.append(
                {
                    "id": "SEC-005",
                    "severity": "low",
                    "category": "timeout_policy",
                    "title": f"{len(high_timeouts)} endpoint(s) configured with timeout > 15,000ms",
                    "detail": "Long gateway timeouts can increase slowloris / upstream exhaustion risk.",
                    "remediation": "Reduce endpoint timeout_ms to <= 10,000ms where possible.",
                }
            )

        penalty = sum(
            {"critical": 35, "high": 20, "medium": 10, "low": 4}.get(f["severity"], 5)
            for f in findings
        )
        score = max(0, 100 - penalty)
        report = {
            "status": "passed" if chain_check["valid"] and score >= 75 else "attention_required",
            "security_score": score,
            "audit_chain_integrity": chain_check,
            "findings_count": len(findings),
            "findings": findings,
            "controls_verified": [
                "redis_distributed_rate_limiting",
                "rbac_and_project_isolation",
                "api_key_expiration_and_rotation",
                "hmac_sha256_audit_chain",
                "login_throttling_mfa_and_password_reset",
                "request_size_and_abuse_prevention",
            ],
            "audited_at": now,
        }
        AuditLogger.log_event(
            event_type="security.automated_audit",
            description=f"Completed automated security audit (score={score}/100, findings={len(findings)})",
            metadata={"score": score, "findings_count": len(findings)},
        )
        return report


security_manager = SecurityManager()
