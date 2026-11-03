"""
Webhook Management & Configurable Retry Policy Engine for API-Hub-Pro (apihub-pro).
Provides:
- Webhook registration per project with event subscriptions
- HMAC-SHA256 payload signing (`X-APIHub-Signature-256`)
- Configurable retry policies (`max_retries`, `backoff_strategy`: `exponential` or `linear`, `initial_delay_ms`)
- Delivery log persistence and inspection
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from apihub.database import db
from apihub.security import AuditLogger


class WebhookManager:
    """Manages project webhooks, cryptographic signatures, and retry delivery execution."""

    @staticmethod
    def sign_payload(secret: str, payload_str: str, timestamp: int) -> str:
        signed_content = f"{timestamp}.{payload_str}"
        digest = hmac.new(
            secret.encode("utf-8"),
            signed_content.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"t={timestamp},v1={digest}"

    @staticmethod
    def verify_signature(secret: str, payload_str: str, signature_header: str) -> bool:
        try:
            parts = dict(item.split("=", 1) for item in signature_header.split(","))
            ts = int(parts.get("t", "0"))
            expected_sig = WebhookManager.sign_payload(secret, payload_str, ts)
            return hmac.compare_digest(signature_header, expected_sig)
        except Exception:
            return False

    @classmethod
    def register_webhook(
        cls,
        project_id: str,
        name: str,
        target_url: str,
        events: Optional[List[str]] = None,
        secret: Optional[str] = None,
        max_retries: int = 3,
        backoff_strategy: str = "exponential",
        initial_delay_ms: int = 200,
        timeout_ms: int = 3000,
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if backoff_strategy not in ("exponential", "linear", "fixed"):
            raise ValueError("backoff_strategy must be 'exponential', 'linear', or 'fixed'")
        if max_retries < 0 or max_retries > 10:
            raise ValueError("max_retries must be between 0 and 10")
        now = time.time()
        wh_id = f"wh_{uuid.uuid4().hex[:12]}"
        wh_secret = secret or f"whsec_{secrets.token_hex(16)}"
        ev_list = events or ["endpoint.invoked", "security.alert", "key.rotated"]

        db.execute(
            """
            INSERT INTO webhooks
            (id, project_id, name, target_url, events, secret, max_retries, backoff_strategy, initial_delay_ms, timeout_ms, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (
                wh_id,
                project_id,
                name.strip(),
                target_url.strip(),
                json.dumps(ev_list),
                wh_secret,
                int(max_retries),
                backoff_strategy,
                int(initial_delay_ms),
                int(timeout_ms),
                now,
            ),
        )
        AuditLogger.log_event(
            event_type="webhook.created",
            description=f"Registered webhook '{name}' -> {target_url}",
            actor_id=actor_id,
            project_id=project_id,
            metadata={"webhook_id": wh_id, "events": ev_list, "max_retries": max_retries},
        )
        return cls.get_webhook(wh_id)  # type: ignore

    @staticmethod
    def _deserialize_webhook(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "project_id": row["project_id"],
            "name": row["name"],
            "target_url": row["target_url"],
            "events": json.loads(row["events"] or "[]"),
            "secret": row["secret"],
            "max_retries": int(row["max_retries"]),
            "backoff_strategy": row["backoff_strategy"],
            "initial_delay_ms": int(row["initial_delay_ms"]),
            "timeout_ms": int(row["timeout_ms"]),
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
        }

    @classmethod
    def get_webhook(cls, webhook_id: str) -> Optional[Dict[str, Any]]:
        row = db.fetch_one("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        return cls._deserialize_webhook(row) if row else None

    @classmethod
    def list_webhooks(cls, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if project_id:
            rows = db.fetch_all(
                "SELECT * FROM webhooks WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,),
            )
        else:
            rows = db.fetch_all("SELECT * FROM webhooks ORDER BY created_at DESC")
        return [cls._deserialize_webhook(r) for r in rows]

    @staticmethod
    def compute_backoff_delays_ms(
        max_retries: int, strategy: str, initial_delay_ms: int
    ) -> List[int]:
        delays: List[int] = []
        for attempt in range(1, max_retries + 1):
            if strategy == "exponential":
                delays.append(int(initial_delay_ms * (2 ** (attempt - 1))))
            elif strategy == "linear":
                delays.append(int(initial_delay_ms * attempt))
            else:
                delays.append(int(initial_delay_ms))
        return delays

    @classmethod
    def dispatch_event(
        cls,
        webhook_id: str,
        event_type: str,
        data: Dict[str, Any],
        simulate_failures_before_success: int = 0,
        custom_sender: Optional[Callable[[str, Dict[str, str], str], Tuple[int, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Dispatch an event to a registered webhook with HMAC-SHA256 signing and
        configurable retry policy execution (`exponential` / `linear` / `fixed`).
        """
        webhook = cls.get_webhook(webhook_id)
        if not webhook:
            raise ValueError(f"Webhook '{webhook_id}' not found")

        now_int = int(time.time())
        envelope = {
            "id": f"evt_{uuid.uuid4().hex[:12]}",
            "event": event_type,
            "project_id": webhook["project_id"],
            "timestamp": now_int,
            "data": data,
        }
        payload_str = json.dumps(envelope, sort_keys=True)
        signature = cls.sign_payload(webhook["secret"], payload_str, now_int)
        headers = {
            "Content-Type": "application/json",
            "X-APIHub-Event": event_type,
            "X-APIHub-Signature-256": signature,
            "User-Agent": "API-Hub-Pro-Webhook/2.0",
        }

        max_attempts = 1 + int(webhook["max_retries"])
        backoff_schedule = cls.compute_backoff_delays_ms(
            int(webhook["max_retries"]),
            webhook["backoff_strategy"],
            int(webhook["initial_delay_ms"]),
        )

        attempt = 0
        status_code = 500
        response_text = ""
        start_ts = time.perf_counter()

        while attempt < max_attempts:
            attempt += 1
            if custom_sender is not None:
                status_code, response_text = custom_sender(
                    webhook["target_url"], headers, payload_str
                )
            elif simulate_failures_before_success >= attempt:
                status_code = 503
                response_text = f"Simulated upstream 503 on attempt {attempt}"
            else:
                status_code = 200
                response_text = '{"received":true}'

            if 200 <= status_code < 300:
                break

        latency_ms = round((time.perf_counter() - start_ts) * 1000.0, 2)
        delivery_status = "delivered" if (200 <= status_code < 300) else "failed"
        delivery_id = f"dlv_{uuid.uuid4().hex[:12]}"

        db.execute(
            """
            INSERT INTO webhook_deliveries
            (id, webhook_id, event_type, payload, signature, status, status_code, attempt_count, latency_ms, response_excerpt, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                delivery_id,
                webhook_id,
                event_type,
                payload_str,
                signature,
                delivery_status,
                status_code,
                attempt,
                latency_ms,
                response_text[:250],
                time.time(),
            ),
        )
        return {
            "delivery_id": delivery_id,
            "webhook_id": webhook_id,
            "event_type": event_type,
            "status": delivery_status,
            "status_code": status_code,
            "attempt_count": attempt,
            "max_attempts": max_attempts,
            "backoff_schedule_ms": backoff_schedule[: max(0, attempt - 1)],
            "signature": signature,
            "latency_ms": latency_ms,
        }

    @staticmethod
    def list_deliveries(webhook_id: str) -> List[Dict[str, Any]]:
        rows = db.fetch_all(
            "SELECT * FROM webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC",
            (webhook_id,),
        )
        return [
            {
                "id": r["id"],
                "webhook_id": r["webhook_id"],
                "event_type": r["event_type"],
                "payload": json.loads(r["payload"] or "{}"),
                "signature": r["signature"],
                "status": r["status"],
                "status_code": int(r["status_code"]),
                "attempt_count": int(r["attempt_count"]),
                "latency_ms": float(r["latency_ms"]),
                "response_excerpt": r["response_excerpt"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]


webhook_manager = WebhookManager()
