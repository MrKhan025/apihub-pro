"""
Advanced Gateway Resilience & Traffic Engineering Module for APIHub-Pro v3.0.
Provides:
- Canary Deployments (weighted traffic routing, sticky headers, automatic rollback on error spike)
- Traffic Shadowing (asynchronous shadow invocation & payload diffing)
- Request Replay Vault (capture & deterministic replay of production requests)
- State-Machine Circuit Breakers (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)
- Dynamic Service Discovery Registry (instance registration, heartbeats, round-robin / least-latency routing)
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional

from apihub.database import db
from apihub.ddd_cqrs import event_store
from apihub.gateway import gateway_manager
from apihub.security import AuditLogger


class ResilienceAndTrafficEngine:
    """Manages canary deployments, traffic shadowing, request replay, circuit breakers, and service discovery."""

    @staticmethod
    def create_canary_deployment(
        project_id: str,
        name: str,
        path: str,
        method: str = "GET",
        stable_version: str = "v1",
        canary_version: str = "v2",
        canary_weight_percent: int = 20,
        auto_rollback_error_pct: float = 15.0,
    ) -> Dict[str, Any]:
        if not (0 <= canary_weight_percent <= 100):
            raise ValueError("canary_weight_percent must be between 0 and 100")
        cid = f"cnr_{uuid.uuid4().hex[:12]}"
        now = time.time()
        norm_path = "/" + path.strip().lstrip("/")
        db.execute(
            """
            INSERT INTO canary_deployments (
                id, project_id, name, path, method, stable_version, canary_version,
                canary_weight_percent, auto_rollback_error_pct,
                total_stable_requests, total_canary_requests, canary_errors, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 'active', ?)
            """,
            (
                cid,
                project_id,
                name.strip(),
                norm_path,
                method.upper(),
                stable_version,
                canary_version,
                int(canary_weight_percent),
                float(auto_rollback_error_pct),
                now,
            ),
        )
        event_store.append(
            aggregate_type="canary",
            aggregate_id=cid,
            event_type="canary.deployment.created",
            payload={"path": norm_path, "canary_weight_percent": canary_weight_percent},
        )
        return dict(db.fetch_one("SELECT * FROM canary_deployments WHERE id = ?", (cid,)) or {})

    @staticmethod
    def list_canary_deployments(project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if project_id:
            rows = db.fetch_all(
                "SELECT * FROM canary_deployments WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,),
            )
        else:
            rows = db.fetch_all("SELECT * FROM canary_deployments ORDER BY created_at DESC")
        return [dict(r) for r in rows]

    @classmethod
    def route_canary_request(
        cls,
        canary_id: str,
        headers: Dict[str, str],
        query_params: Dict[str, Any],
        body: Any,
        routing_key: Optional[str] = None,
        simulate_canary_error: bool = False,
    ) -> Dict[str, Any]:
        row = db.fetch_one("SELECT * FROM canary_deployments WHERE id = ?", (canary_id,))
        if not row:
            raise ValueError(f"Canary deployment '{canary_id}' not found")

        weight = int(row["canary_weight_percent"]) if row["status"] == "active" else 0
        force_canary = str(headers.get("X-Canary", headers.get("x-canary", ""))).lower() == "true"

        if force_canary:
            selected_target = "canary"
        elif weight <= 0:
            selected_target = "stable"
        elif weight >= 100:
            selected_target = "canary"
        else:
            total_so_far = int(row["total_stable_requests"]) + int(row["total_canary_requests"])
            if routing_key:
                bucket = int(hashlib.sha256(routing_key.encode("utf-8")).hexdigest()[:8], 16) % 100
            else:
                bucket = (total_so_far * 37) % 100
            selected_target = "canary" if bucket < weight else "stable"

        target_version = row["canary_version"] if selected_target == "canary" else row["stable_version"]
        status_code, resp_headers, resp_body, _, latency_ms, _ = gateway_manager.resolve_and_execute(
            version=target_version,
            path=row["path"],
            method=row["method"],
            headers=headers,
            query_params=query_params,
            body=body,
            project_id=row["project_id"],
        )

        if selected_target == "canary" and simulate_canary_error:
            status_code = 500
            resp_body = {"error": "Simulated canary upstream failure"}

        new_stable = int(row["total_stable_requests"]) + (1 if selected_target == "stable" else 0)
        new_canary = int(row["total_canary_requests"]) + (1 if selected_target == "canary" else 0)
        new_errors = int(row["canary_errors"]) + (1 if selected_target == "canary" and status_code >= 500 else 0)
        new_status = row["status"]

        canary_err_pct = (new_errors / new_canary * 100.0) if new_canary > 0 else 0.0
        if new_canary >= 2 and canary_err_pct >= float(row["auto_rollback_error_pct"]):
            new_status = "rolled_back"
            AuditLogger.log_event(
                event_type="gateway.canary_auto_rollback",
                severity="high",
                description=f"Auto-rolled back canary {canary_id} (error rate {canary_err_pct:.1f}%)",
                project_id=row["project_id"],
            )

        db.execute(
            """
            UPDATE canary_deployments
            SET total_stable_requests = ?, total_canary_requests = ?, canary_errors = ?, status = ?
            WHERE id = ?
            """,
            (new_stable, new_canary, new_errors, new_status, canary_id),
        )
        return {
            "canary_id": canary_id,
            "routed_to": selected_target,
            "version_used": target_version,
            "status_code": status_code,
            "deployment_status": new_status,
            "canary_error_rate_percent": round(canary_err_pct, 2),
            "latency_ms": round(latency_ms, 2),
            "response": resp_body,
        }

    @staticmethod
    def execute_shadow_traffic(
        project_id: str,
        path: str,
        method: str,
        primary_version: str,
        shadow_version: str,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        body: Any = None,
    ) -> Dict[str, Any]:
        req_h = headers or {}
        req_q = query_params or {}

        p_status, _, p_body, _, p_lat, _ = gateway_manager.resolve_and_execute(
            version=primary_version,
            path=path,
            method=method,
            headers=req_h,
            query_params=req_q,
            body=body,
            project_id=project_id,
        )
        s_status, _, s_body, _, s_lat, _ = gateway_manager.resolve_and_execute(
            version=shadow_version,
            path=path,
            method=method,
            headers={**req_h, "X-Traffic-Shadow": "true"},
            query_params=req_q,
            body=body,
            project_id=project_id,
        )

        status_match = p_status == s_status
        body_match = p_body == s_body
        return {
            "mode": "traffic_shadowing",
            "path": path,
            "method": method.upper(),
            "primary": {
                "version": primary_version,
                "status_code": p_status,
                "latency_ms": round(p_lat, 2),
                "body": p_body,
            },
            "shadow": {
                "version": shadow_version,
                "status_code": s_status,
                "latency_ms": round(s_lat, 2),
                "body": s_body,
            },
            "comparison": {
                "status_match": status_match,
                "payload_identical": body_match,
                "latency_delta_ms": round(s_lat - p_lat, 2),
            },
        }

    @staticmethod
    def capture_request_for_replay(
        project_id: str,
        version: str,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        body: Any = None,
        original_status: int = 200,
        original_latency_ms: float = 5.0,
    ) -> Dict[str, Any]:
        cap_id = f"rpl_{uuid.uuid4().hex[:12]}"
        now = time.time()
        norm_path = "/" + path.strip().lstrip("/")
        db.execute(
            """
            INSERT INTO replay_vault (
                id, project_id, version, method, path, headers, query_params, body,
                original_status, original_latency_ms, replay_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                cap_id,
                project_id,
                version,
                method.upper(),
                norm_path,
                json.dumps(headers or {}),
                json.dumps(query_params or {}),
                json.dumps(body if body is not None else {}),
                int(original_status),
                float(original_latency_ms),
                now,
            ),
        )
        return dict(db.fetch_one("SELECT * FROM replay_vault WHERE id = ?", (cap_id,)) or {})

    @staticmethod
    def execute_request_replay(capture_id: str, target_version_override: Optional[str] = None) -> Dict[str, Any]:
        row = db.fetch_one("SELECT * FROM replay_vault WHERE id = ?", (capture_id,))
        if not row:
            raise ValueError(f"Replay capture '{capture_id}' not found")

        version = target_version_override or row["version"]
        headers = json.loads(row["headers"] or "{}")
        query_params = json.loads(row["query_params"] or "{}")
        body = json.loads(row["body"] or "{}")

        status_code, resp_headers, resp_body, _, latency_ms, _ = gateway_manager.resolve_and_execute(
            version=version,
            path=row["path"],
            method=row["method"],
            headers={**headers, "X-Replayed-Request-Id": capture_id},
            query_params=query_params,
            body=body,
            project_id=row["project_id"],
        )

        new_count = int(row["replay_count"]) + 1
        db.execute(
            "UPDATE replay_vault SET replay_count = ?, last_replay_status = ? WHERE id = ?",
            (new_count, status_code, capture_id),
        )
        return {
            "capture_id": capture_id,
            "replayed_version": version,
            "method": row["method"],
            "path": row["path"],
            "original_status": int(row["original_status"]),
            "replay_status": status_code,
            "status_regression_detected": status_code != int(row["original_status"]),
            "replay_count": new_count,
            "latency_ms": round(latency_ms, 2),
            "response": resp_body,
        }

    @staticmethod
    def configure_circuit_breaker(
        service_name: str,
        failure_threshold: int = 3,
        recovery_timeout_seconds: int = 30,
        half_open_max_calls: int = 2,
    ) -> Dict[str, Any]:
        now = time.time()
        db.execute(
            """
            INSERT INTO circuit_breakers
            (service_name, state, failure_count, success_count, failure_threshold, recovery_timeout_seconds, half_open_max_calls, last_failure_at, updated_at)
            VALUES (?, 'CLOSED', 0, 0, ?, ?, ?, 0, ?)
            ON CONFLICT(service_name) DO UPDATE SET
                failure_threshold = excluded.failure_threshold,
                recovery_timeout_seconds = excluded.recovery_timeout_seconds,
                half_open_max_calls = excluded.half_open_max_calls,
                updated_at = excluded.updated_at
            """,
            (service_name, int(failure_threshold), int(recovery_timeout_seconds), int(half_open_max_calls), now),
        )
        return dict(db.fetch_one("SELECT * FROM circuit_breakers WHERE service_name = ?", (service_name,)) or {})

    @classmethod
    def check_and_record_circuit_breaker(
        cls,
        service_name: str,
        call_succeeded: Optional[bool] = None,
        now_override: Optional[float] = None,
    ) -> Dict[str, Any]:
        now = now_override if now_override is not None else time.time()
        cb = db.fetch_one("SELECT * FROM circuit_breakers WHERE service_name = ?", (service_name,))
        if not cb:
            cb = cls.configure_circuit_breaker(service_name)

        state = cb["state"]
        failures = int(cb["failure_count"])
        successes = int(cb["success_count"])
        threshold = int(cb["failure_threshold"])
        recovery_secs = int(cb["recovery_timeout_seconds"])
        half_open_target = int(cb["half_open_max_calls"])
        last_fail = float(cb["last_failure_at"] or 0.0)

        if state == "OPEN":
            if (now - last_fail) >= recovery_secs:
                state = "HALF_OPEN"
                successes = 0
            else:
                return {
                    "service_name": service_name,
                    "allowed": False,
                    "state": "OPEN",
                    "failure_count": failures,
                    "retry_after_seconds": max(1, int(recovery_secs - (now - last_fail))),
                }

        if call_succeeded is True:
            if state == "HALF_OPEN":
                successes += 1
                if successes >= half_open_target:
                    state = "CLOSED"
                    failures = 0
                    successes = 0
            else:
                failures = 0
                successes += 1
        elif call_succeeded is False:
            failures += 1
            last_fail = now
            if state == "HALF_OPEN" or failures >= threshold:
                state = "OPEN"
                successes = 0

        db.execute(
            """
            UPDATE circuit_breakers
            SET state = ?, failure_count = ?, success_count = ?, last_failure_at = ?, updated_at = ?
            WHERE service_name = ?
            """,
            (state, failures, successes, last_fail, now, service_name),
        )
        return {
            "service_name": service_name,
            "allowed": state != "OPEN",
            "state": state,
            "failure_count": failures,
            "success_count": successes,
            "failure_threshold": threshold,
        }

    @staticmethod
    def register_service_instance(
        service_name: str,
        instance_url: str,
        version: str = "v1",
        weight: int = 100,
        avg_latency_ms: float = 5.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        inst_id = f"svc_{uuid.uuid4().hex[:12]}"
        now = time.time()
        db.execute(
            """
            INSERT INTO service_registry
            (id, service_name, instance_url, version, weight, status, avg_latency_ms, metadata, last_heartbeat_at, created_at)
            VALUES (?, ?, ?, ?, ?, 'healthy', ?, ?, ?, ?)
            """,
            (
                inst_id,
                service_name.strip(),
                instance_url.strip(),
                version,
                int(weight),
                float(avg_latency_ms),
                json.dumps(metadata or {}),
                now,
                now,
            ),
        )
        return {
            "id": inst_id,
            "service_name": service_name.strip(),
            "instance_url": instance_url.strip(),
            "version": version,
            "weight": int(weight),
            "status": "healthy",
            "avg_latency_ms": float(avg_latency_ms),
            "metadata": metadata or {},
        }

    @staticmethod
    def list_services(service_name: Optional[str] = None) -> List[Dict[str, Any]]:
        if service_name:
            rows = db.fetch_all(
                "SELECT * FROM service_registry WHERE service_name = ? ORDER BY avg_latency_ms ASC",
                (service_name,),
            )
        else:
            rows = db.fetch_all("SELECT * FROM service_registry ORDER BY service_name ASC, avg_latency_ms ASC")
        return [
            {**dict(r), "metadata": json.loads(r["metadata"] or "{}")}
            for r in rows
        ]

    @classmethod
    def resolve_service_instance(
        cls, service_name: str, strategy: str = "least_latency"
    ) -> Dict[str, Any]:
        instances = [
            s for s in cls.list_services(service_name) if s["status"] == "healthy"
        ]
        if not instances:
            raise ValueError(f"No healthy instances registered for service '{service_name}'")
        if strategy == "least_latency":
            instances.sort(key=lambda x: float(x["avg_latency_ms"]))
            chosen = instances[0]
        else:
            idx = int(time.time() * 1000) % len(instances)
            chosen = instances[idx]
        return {
            "service_name": service_name,
            "strategy": strategy,
            "selected_instance": chosen,
            "candidate_count": len(instances),
        }


resilience_engine = ResilienceAndTrafficEngine()
