"""
Enterprise Observability Module for APIHub-Pro v3.0.
Provides:
- Prometheus Exposition Format Metrics (`/metrics`)
- OpenTelemetry W3C Trace Context (`traceparent` / `tracestate`) Distributed Tracing & Span Collector
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Any, Dict, List, Optional

from apihub.analytics import analytics_engine
from apihub.database import db


class DistributedTraceCollector:
    """OpenTelemetry-compatible W3C Trace Context span recorder."""

    def __init__(self, max_traces: int = 250) -> None:
        self._lock = threading.RLock()
        self._traces: Dict[str, Dict[str, Any]] = {}
        self._order: List[str] = []
        self.max_traces = max_traces

    @staticmethod
    def parse_or_create_traceparent(header_val: Optional[str]) -> Dict[str, str]:
        if header_val:
            parts = header_val.strip().split("-")
            if len(parts) == 4 and len(parts[1]) == 32 and len(parts[2]) == 16:
                new_span_id = secrets.token_hex(8)
                return {
                    "version": parts[0],
                    "trace_id": parts[1],
                    "parent_span_id": parts[2],
                    "span_id": new_span_id,
                    "traceparent": f"00-{parts[1]}-{new_span_id}-{parts[3]}",
                }
        trace_id = secrets.token_hex(16)
        span_id = secrets.token_hex(8)
        return {
            "version": "00",
            "trace_id": trace_id,
            "parent_span_id": "0000000000000000",
            "span_id": span_id,
            "traceparent": f"00-{trace_id}-{span_id}-01",
        }

    def record_trace(
        self,
        trace_ctx: Dict[str, str],
        method: str,
        path: str,
        status_code: int,
        duration_ms: float,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        trace_id = trace_ctx["trace_id"]
        span_record = {
            "trace_id": trace_id,
            "span_id": trace_ctx["span_id"],
            "parent_span_id": trace_ctx["parent_span_id"],
            "traceparent": trace_ctx["traceparent"],
            "name": f"{method.upper()} {path}",
            "kind": "SERVER",
            "status_code": int(status_code),
            "duration_ms": round(duration_ms, 2),
            "attributes": {
                "http.method": method.upper(),
                "http.route": path,
                "http.status_code": int(status_code),
                "service.name": "apihub-pro-gateway",
                **(attributes or {}),
            },
            "child_spans": [
                {
                    "span_id": secrets.token_hex(8),
                    "name": "gateway.security_guard",
                    "duration_ms": round(duration_ms * 0.15, 2),
                },
                {
                    "span_id": secrets.token_hex(8),
                    "name": "gateway.rate_limit_and_dispatch",
                    "duration_ms": round(duration_ms * 0.85, 2),
                },
            ],
            "timestamp": now,
        }
        with self._lock:
            self._traces[trace_id] = span_record
            self._order.append(trace_id)
            while len(self._order) > self.max_traces:
                oldest = self._order.pop(0)
                self._traces.pop(oldest, None)
        return span_record

    def list_traces(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            recent_ids = list(reversed(self._order[-limit:]))
            return [self._traces[tid] for tid in recent_ids if tid in self._traces]

    def get_trace(self, trace_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._traces.get(trace_id)


class PrometheusMetricsExporter:
    """Generates Prometheus text exposition format metrics (`/metrics`)."""

    @staticmethod
    def render_metrics() -> str:
        summary = analytics_engine.get_summary()
        lat = summary["latency_percentiles"]
        sb = summary["status_breakdown"]

        ai_rows = db.fetch_all("SELECT provider, total_tokens, cost_usd FROM ai_gateway_logs")
        total_ai_tokens = sum(int(r["total_tokens"]) for r in ai_rows)
        total_ai_cost = round(sum(float(r["cost_usd"]) for r in ai_rows), 6)

        cb_rows = db.fetch_all("SELECT service_name, state, failure_count FROM circuit_breakers")
        canary_count = len(db.fetch_all("SELECT id FROM canary_deployments WHERE status = 'active'"))

        lines = [
            "# HELP apihub_http_requests_total Total HTTP requests processed by APIHub-Pro Gateway",
            "# TYPE apihub_http_requests_total counter",
            f'apihub_http_requests_total{{status_class="2xx"}} {sb.get("2xx", 0)}',
            f'apihub_http_requests_total{{status_class="4xx"}} {sb.get("4xx", 0)}',
            f'apihub_http_requests_total{{status_class="5xx"}} {sb.get("5xx", 0)}',
            "# HELP apihub_http_latency_milliseconds HTTP request latency percentiles in ms",
            "# TYPE apihub_http_latency_milliseconds gauge",
            f'apihub_http_latency_milliseconds{{quantile="0.5"}} {lat.get("p50_ms", 0.0)}',
            f'apihub_http_latency_milliseconds{{quantile="0.9"}} {lat.get("p90_ms", 0.0)}',
            f'apihub_http_latency_milliseconds{{quantile="0.95"}} {lat.get("p95_ms", 0.0)}',
            f'apihub_http_latency_milliseconds{{quantile="0.99"}} {lat.get("p99_ms", 0.0)}',
            "# HELP apihub_ai_tokens_total Total LLM tokens processed by the AI Gateway",
            "# TYPE apihub_ai_tokens_total counter",
            f"apihub_ai_tokens_total {total_ai_tokens}",
            "# HELP apihub_ai_cost_usd_total Total cumulative AI Gateway spend in USD",
            "# TYPE apihub_ai_cost_usd_total counter",
            f"apihub_ai_cost_usd_total {total_ai_cost}",
            "# HELP apihub_active_canary_deployments Number of active canary traffic splits",
            "# TYPE apihub_active_canary_deployments gauge",
            f"apihub_active_canary_deployments {canary_count}",
        ]
        for cb in cb_rows:
            state_num = 0 if cb["state"] == "CLOSED" else (1 if cb["state"] == "HALF_OPEN" else 2)
            lines.append(
                f'apihub_circuit_breaker_state{{service="{cb["service_name"]}"}} {state_num}'
            )
        return "\n".join(lines) + "\n"


trace_collector = DistributedTraceCollector()
prometheus_exporter = PrometheusMetricsExporter()
