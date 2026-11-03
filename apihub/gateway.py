"""
Dynamic API Gateway Engine for API-Hub-Pro (apihub-pro).
Provides:
- Dynamic API endpoint registration without manually writing code routes
- API versioning (`v1`, `v2`, custom versions) & lifecycle management (`draft`, `active`, `deprecated`, `retired`)
- Request and response transformation pipeline (header injection/removal, JSON field mapping, field masking, envelope wrapping)
- Configurable per-endpoint request timeouts (`timeout_ms`) with `504 Gateway Timeout` enforcement
- Redis response caching for idempotent GET endpoints
"""

from __future__ import annotations

import copy
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from apihub.config import settings
from apihub.database import db
from apihub.rate_limiter import response_cache
from apihub.security import AuditLogger


VALID_LIFECYCLE_STATES = ("draft", "active", "deprecated", "retired")
VALID_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


class TransformPipeline:
    """Applies declarative request and response transformations."""

    @staticmethod
    def transform_request(
        headers: Dict[str, str],
        query_params: Dict[str, Any],
        body: Any,
        rules: Dict[str, Any],
    ) -> Tuple[Dict[str, str], Dict[str, Any], Any]:
        out_headers = dict(headers)
        out_query = dict(query_params)
        out_body = copy.deepcopy(body) if isinstance(body, (dict, list)) else body

        for h_key, h_val in (rules.get("add_headers") or {}).items():
            out_headers[str(h_key)] = str(h_val)
        for h_remove in rules.get("remove_headers") or []:
            out_headers.pop(str(h_remove), None)
            out_headers.pop(str(h_remove).lower(), None)

        for q_key, q_val in (rules.get("default_query_params") or {}).items():
            out_query.setdefault(str(q_key), q_val)

        if isinstance(out_body, dict):
            for old_key, new_key in (rules.get("rename_body_fields") or {}).items():
                if old_key in out_body:
                    out_body[str(new_key)] = out_body.pop(old_key)
            for inject_k, inject_v in (rules.get("inject_body_fields") or {}).items():
                out_body[str(inject_k)] = inject_v
            for strip_k in rules.get("remove_body_fields") or []:
                out_body.pop(str(strip_k), None)

        return out_headers, out_query, out_body

    @staticmethod
    def transform_response(
        status_code: int,
        headers: Dict[str, str],
        body: Any,
        rules: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Tuple[int, Dict[str, str], Any]:
        out_headers = dict(headers)
        out_body = copy.deepcopy(body) if isinstance(body, (dict, list)) else body

        for h_key, h_val in (rules.get("add_headers") or {}).items():
            out_headers[str(h_key)] = str(h_val)
        for h_remove in rules.get("remove_headers") or []:
            out_headers.pop(str(h_remove), None)

        if isinstance(out_body, dict):
            for old_key, new_key in (rules.get("rename_fields") or {}).items():
                if old_key in out_body:
                    out_body[str(new_key)] = out_body.pop(old_key)
            for mask_field in rules.get("mask_fields") or []:
                if mask_field in out_body and out_body[mask_field] is not None:
                    val_str = str(out_body[mask_field])
                    out_body[mask_field] = (
                        "***" + val_str[-4:] if len(val_str) > 4 else "****"
                    )
            for remove_field in rules.get("remove_fields") or []:
                out_body.pop(str(remove_field), None)
            for k, v in (rules.get("inject_fields") or {}).items():
                out_body[str(k)] = v

        if rules.get("wrap_envelope"):
            envelope_key = str(rules.get("envelope_key", "data"))
            out_body = {
                envelope_key: out_body,
                "meta": {
                    "version": context.get("version", "v1"),
                    "endpoint": context.get("path", ""),
                    "transformed": True,
                },
            }

        override_status = rules.get("override_status_code")
        if override_status is not None:
            status_code = int(override_status)

        return status_code, out_headers, out_body


class GatewayManager:
    """Manages dynamic endpoint registration, versioning, lifecycle transitions, and runtime execution."""

    @staticmethod
    def _normalize_path(path: str) -> str:
        clean = "/" + path.strip().lstrip("/")
        return clean.rstrip("/") if len(clean) > 1 else clean

    @classmethod
    def register_endpoint(
        cls,
        project_id: str,
        name: str,
        path: str,
        method: str = "GET",
        version: str = "v1",
        lifecycle_state: str = "active",
        deprecation_date: Optional[str] = None,
        sunset_date: Optional[str] = None,
        timeout_ms: int = 5000,
        cache_ttl_seconds: int = 0,
        auth_required: bool = True,
        rate_limit_rpm: int = 60,
        response_mode: str = "mock",
        upstream_url: Optional[str] = None,
        mock_status_code: int = 200,
        mock_response_body: Optional[Dict[str, Any]] = None,
        mock_headers: Optional[Dict[str, str]] = None,
        simulated_latency_ms: int = 0,
        request_transform: Optional[Dict[str, Any]] = None,
        response_transform: Optional[Dict[str, Any]] = None,
        description: str = "",
        tags: Optional[List[str]] = None,
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        norm_method = method.strip().upper()
        if norm_method not in VALID_HTTP_METHODS:
            raise ValueError(f"Unsupported HTTP method '{norm_method}'")
        if lifecycle_state not in VALID_LIFECYCLE_STATES:
            raise ValueError(f"Invalid lifecycle_state '{lifecycle_state}'")
        if timeout_ms <= 0 or timeout_ms > settings.max_gateway_timeout_ms:
            raise ValueError(
                f"timeout_ms must be between 1 and {settings.max_gateway_timeout_ms}"
            )

        norm_path = cls._normalize_path(path)
        norm_version = version.strip().lstrip("/") or "v1"
        now = time.time()
        endpoint_id = f"ep_{uuid.uuid4().hex[:12]}"

        db.execute(
            """
            INSERT INTO dynamic_endpoints (
                id, project_id, name, version, path, method, lifecycle_state,
                deprecation_date, sunset_date, timeout_ms, cache_ttl_seconds,
                auth_required, rate_limit_rpm, response_mode, upstream_url,
                mock_status_code, mock_response_body, mock_headers, simulated_latency_ms,
                request_transform, response_transform, description, tags, created_by,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                endpoint_id,
                project_id,
                name.strip(),
                norm_version,
                norm_path,
                norm_method,
                lifecycle_state,
                deprecation_date,
                sunset_date,
                int(timeout_ms),
                int(cache_ttl_seconds),
                1 if auth_required else 0,
                int(rate_limit_rpm),
                response_mode,
                upstream_url,
                int(mock_status_code),
                json.dumps(mock_response_body if mock_response_body is not None else {"status": "ok"}),
                json.dumps(mock_headers or {}),
                int(simulated_latency_ms),
                json.dumps(request_transform or {}),
                json.dumps(response_transform or {}),
                description,
                json.dumps(tags or []),
                actor_id,
                now,
                now,
            ),
        )
        AuditLogger.log_event(
            event_type="gateway.endpoint_registered",
            description=f"Registered dynamic endpoint {norm_method} /gateway/{norm_version}{norm_path}",
            actor_id=actor_id,
            project_id=project_id,
            metadata={
                "endpoint_id": endpoint_id,
                "version": norm_version,
                "path": norm_path,
                "method": norm_method,
                "lifecycle_state": lifecycle_state,
            },
        )
        return cls.get_endpoint(endpoint_id)  # type: ignore

    @staticmethod
    def _deserialize_endpoint(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "project_id": row["project_id"],
            "name": row["name"],
            "version": row["version"],
            "path": row["path"],
            "full_gateway_path": f"/gateway/{row['version']}{row['path']}",
            "method": row["method"],
            "lifecycle_state": row["lifecycle_state"],
            "deprecation_date": row["deprecation_date"],
            "sunset_date": row["sunset_date"],
            "timeout_ms": int(row["timeout_ms"]),
            "cache_ttl_seconds": int(row["cache_ttl_seconds"]),
            "auth_required": bool(row["auth_required"]),
            "rate_limit_rpm": int(row["rate_limit_rpm"]),
            "response_mode": row["response_mode"],
            "upstream_url": row["upstream_url"],
            "mock_status_code": int(row["mock_status_code"]),
            "mock_response_body": json.loads(row["mock_response_body"] or "{}"),
            "mock_headers": json.loads(row["mock_headers"] or "{}"),
            "simulated_latency_ms": int(row["simulated_latency_ms"]),
            "request_transform": json.loads(row["request_transform"] or "{}"),
            "response_transform": json.loads(row["response_transform"] or "{}"),
            "description": row["description"] or "",
            "tags": json.loads(row["tags"] or "[]"),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @classmethod
    def get_endpoint(cls, endpoint_id: str) -> Optional[Dict[str, Any]]:
        row = db.fetch_one("SELECT * FROM dynamic_endpoints WHERE id = ?", (endpoint_id,))
        return cls._deserialize_endpoint(row) if row else None

    @classmethod
    def list_endpoints(
        cls,
        project_id: Optional[str] = None,
        version: Optional[str] = None,
        lifecycle_state: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses = ["1=1"]
        params: List[Any] = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        if version:
            clauses.append("version = ?")
            params.append(version)
        if lifecycle_state:
            clauses.append("lifecycle_state = ?")
            params.append(lifecycle_state)
        sql = f"SELECT * FROM dynamic_endpoints WHERE {' AND '.join(clauses)} ORDER BY created_at DESC"  # nosec B608
        rows = db.fetch_all(sql, tuple(params))
        return [cls._deserialize_endpoint(r) for r in rows]

    @classmethod
    def update_endpoint(
        cls,
        endpoint_id: str,
        updates: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        existing = cls.get_endpoint(endpoint_id)
        if not existing:
            raise ValueError(f"Endpoint '{endpoint_id}' not found")

        if "lifecycle_state" in updates and updates["lifecycle_state"] not in VALID_LIFECYCLE_STATES:
            raise ValueError(f"Invalid lifecycle_state '{updates['lifecycle_state']}'")
        if "timeout_ms" in updates:
            t_ms = int(updates["timeout_ms"])
            if t_ms <= 0 or t_ms > settings.max_gateway_timeout_ms:
                raise ValueError(
                    f"timeout_ms must be between 1 and {settings.max_gateway_timeout_ms}"
                )

        merged = {**existing, **updates}
        now = time.time()
        db.execute(
            """
            UPDATE dynamic_endpoints SET
                name = ?, version = ?, path = ?, method = ?, lifecycle_state = ?,
                deprecation_date = ?, sunset_date = ?, timeout_ms = ?, cache_ttl_seconds = ?,
                auth_required = ?, rate_limit_rpm = ?, response_mode = ?, upstream_url = ?,
                mock_status_code = ?, mock_response_body = ?, mock_headers = ?,
                simulated_latency_ms = ?, request_transform = ?, response_transform = ?,
                description = ?, tags = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                merged["name"],
                merged["version"],
                cls._normalize_path(merged["path"]),
                merged["method"].upper(),
                merged["lifecycle_state"],
                merged.get("deprecation_date"),
                merged.get("sunset_date"),
                int(merged["timeout_ms"]),
                int(merged["cache_ttl_seconds"]),
                1 if merged["auth_required"] else 0,
                int(merged["rate_limit_rpm"]),
                merged["response_mode"],
                merged.get("upstream_url"),
                int(merged["mock_status_code"]),
                json.dumps(merged["mock_response_body"]),
                json.dumps(merged["mock_headers"]),
                int(merged["simulated_latency_ms"]),
                json.dumps(merged["request_transform"]),
                json.dumps(merged["response_transform"]),
                merged.get("description", ""),
                json.dumps(merged.get("tags", [])),
                now,
                endpoint_id,
            ),
        )
        AuditLogger.log_event(
            event_type="gateway.endpoint_updated",
            description=f"Updated endpoint {endpoint_id} (lifecycle={merged['lifecycle_state']})",
            actor_id=actor_id,
            project_id=existing["project_id"],
            metadata={"endpoint_id": endpoint_id, "updated_fields": list(updates.keys())},
        )
        return cls.get_endpoint(endpoint_id)  # type: ignore

    @classmethod
    def delete_endpoint(cls, endpoint_id: str, actor_id: Optional[str] = None) -> bool:
        existing = cls.get_endpoint(endpoint_id)
        if not existing:
            return False
        db.execute("DELETE FROM dynamic_endpoints WHERE id = ?", (endpoint_id,))
        AuditLogger.log_event(
            event_type="gateway.endpoint_deleted",
            description=f"Deleted endpoint {existing['method']} /gateway/{existing['version']}{existing['path']}",
            actor_id=actor_id,
            project_id=existing["project_id"],
        )
        return True

    @classmethod
    def resolve_and_execute(
        cls,
        version: str,
        path: str,
        method: str,
        headers: Dict[str, str],
        query_params: Dict[str, Any],
        body: Any,
        project_id: Optional[str] = None,
    ) -> Tuple[int, Dict[str, str], Any, Optional[Dict[str, Any]], float, bool]:
        """
        Resolve a registered dynamic endpoint and execute it with lifecycle enforcement,
        request/response transformation, timeout protection, and Redis response caching.
        Returns: (status_code, response_headers, response_body, endpoint_dict, latency_ms, cache_hit)
        """
        start_ts = time.perf_counter()
        norm_path = cls._normalize_path(path)
        norm_method = method.upper()
        norm_version = version.strip().lstrip("/")

        if project_id:
            row = db.fetch_one(
                """
                SELECT * FROM dynamic_endpoints
                WHERE project_id = ? AND version = ? AND path = ? AND method = ?
                """,
                (project_id, norm_version, norm_path, norm_method),
            )
        else:
            row = db.fetch_one(
                """
                SELECT * FROM dynamic_endpoints
                WHERE version = ? AND path = ? AND method = ?
                ORDER BY created_at ASC LIMIT 1
                """,
                (norm_version, norm_path, norm_method),
            )

        if not row:
            latency_ms = (time.perf_counter() - start_ts) * 1000.0
            return (
                404,
                {"X-APIHub-Gateway": "v2.0"},
                {
                    "error": "Dynamic endpoint not found",
                    "version": norm_version,
                    "path": norm_path,
                    "method": norm_method,
                },
                None,
                latency_ms,
                False,
            )

        endpoint = cls._deserialize_endpoint(row)
        state = endpoint["lifecycle_state"]
        resp_headers: Dict[str, str] = {
            "X-APIHub-Gateway": "v2.0",
            "X-APIHub-Endpoint-Id": endpoint["id"],
            "X-APIHub-Version": endpoint["version"],
            "X-APIHub-Lifecycle": state,
        }

        # Enforce lifecycle rules
        if state == "draft":
            latency_ms = (time.perf_counter() - start_ts) * 1000.0
            return (
                403,
                resp_headers,
                {
                    "error": "Endpoint is currently in 'draft' lifecycle state and not yet active",
                    "lifecycle_state": "draft",
                },
                endpoint,
                latency_ms,
                False,
            )

        if state == "retired":
            latency_ms = (time.perf_counter() - start_ts) * 1000.0
            return (
                410,
                resp_headers,
                {
                    "error": "Endpoint has been retired and is no longer available",
                    "lifecycle_state": "retired",
                    "sunset_date": endpoint.get("sunset_date"),
                },
                endpoint,
                latency_ms,
                False,
            )

        if state == "deprecated":
            resp_headers["Deprecation"] = endpoint.get("deprecation_date") or "true"
            if endpoint.get("sunset_date"):
                resp_headers["Sunset"] = str(endpoint["sunset_date"])
            resp_headers["Warning"] = '299 - "Deprecated API endpoint; please migrate to newer version"'

        # Check Redis response cache for GET endpoints
        cache_ttl = int(endpoint.get("cache_ttl_seconds", 0))
        cache_key = ""
        if norm_method == "GET" and cache_ttl > 0:
            cache_key = response_cache.make_cache_key(
                endpoint["project_id"], norm_version, norm_method, norm_path, query_params
            )
            cached = response_cache.get_cached_response(cache_key)
            if cached is not None:
                latency_ms = (time.perf_counter() - start_ts) * 1000.0
                cached_headers = {**resp_headers, **cached.get("headers", {}), "X-Cache": "HIT"}
                return (
                    int(cached["status_code"]),
                    cached_headers,
                    cached["body"],
                    endpoint,
                    latency_ms,
                    True,
                )

        # Apply Request Transformations
        req_headers, req_query, req_body = TransformPipeline.transform_request(
            headers=headers,
            query_params=query_params,
            body=body,
            rules=endpoint["request_transform"],
        )

        # Enforce Configurable Request Timeout
        timeout_ms = int(endpoint["timeout_ms"])
        sim_latency_ms = int(endpoint["simulated_latency_ms"])
        if sim_latency_ms > timeout_ms:
            latency_ms = float(timeout_ms)
            resp_headers["X-APIHub-Timeout-Ms"] = str(timeout_ms)
            return (
                504,
                resp_headers,
                {
                    "error": "Gateway Timeout",
                    "message": f"Endpoint execution exceeded configured timeout of {timeout_ms}ms",
                    "timeout_ms": timeout_ms,
                },
                endpoint,
                latency_ms,
                False,
            )

        if sim_latency_ms > 0:
            time.sleep(min(sim_latency_ms, 250) / 1000.0)

        # Build base response from mock / echo / dynamic template
        mode = endpoint["response_mode"]
        raw_status = int(endpoint["mock_status_code"])
        base_headers = {**resp_headers, **endpoint["mock_headers"]}

        if mode == "echo":
            raw_body: Any = {
                "echo": {
                    "method": norm_method,
                    "version": norm_version,
                    "path": norm_path,
                    "query": req_query,
                    "headers_received": {
                        k: v
                        for k, v in req_headers.items()
                        if k.lower().startswith("x-") or k.lower() in ("content-type", "user-agent")
                    },
                    "body": req_body,
                }
            }
        else:
            raw_body = copy.deepcopy(endpoint["mock_response_body"])
            if isinstance(raw_body, dict) and req_query:
                raw_body.setdefault("_query", req_query)
            if isinstance(raw_body, dict) and req_body not in (None, {}, ""):
                raw_body.setdefault("_request_body", req_body)

        # Apply Response Transformations
        final_status, final_headers, final_body = TransformPipeline.transform_response(
            status_code=raw_status,
            headers=base_headers,
            body=raw_body,
            rules=endpoint["response_transform"],
            context={"version": norm_version, "path": norm_path, "method": norm_method},
        )

        if norm_method == "GET" and cache_ttl > 0 and cache_key:
            final_headers["X-Cache"] = "MISS"
            response_cache.set_cached_response(
                cache_key,
                {"status_code": final_status, "headers": final_headers, "body": final_body},
                ttl_seconds=cache_ttl,
            )

        latency_ms = max((time.perf_counter() - start_ts) * 1000.0, float(sim_latency_ms))
        return final_status, final_headers, final_body, endpoint, latency_ms, False


gateway_manager = GatewayManager()
