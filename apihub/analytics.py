"""
Live Operational Analytics & Reporting Engine for API-Hub-Pro (apihub-pro).
Provides:
- Requests per minute (RPM) and daily usage aggregation
- Latency percentiles (`p50`, `p90`, `p95`, `p99`, `avg`, `min`, `max`)
- Error rate (4xx, 5xx) and per-endpoint performance rankings
- Usage chart SVG generation and exportable CSV / JSON reports
"""

from __future__ import annotations

import csv
import io
import json
import math
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apihub.database import db
from apihub.rate_limiter import response_cache


def compute_percentile(sorted_vals: List[float], percentile: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return round(float(sorted_vals[0]), 2)
    rank = (percentile / 100.0) * (len(sorted_vals) - 1)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    weight = rank - lower
    val = sorted_vals[lower] * (1.0 - weight) + sorted_vals[upper] * weight
    return round(float(val), 2)


class AnalyticsEngine:
    """Records gateway request metrics and computes live percentiles, RPM series, and exportable reports."""

    @staticmethod
    def record_request(
        project_id: str,
        version: str,
        method: str,
        path: str,
        status_code: int,
        latency_ms: float,
        endpoint_id: Optional[str] = None,
        api_key_id: Optional[str] = None,
        request_bytes: int = 0,
        response_bytes: int = 0,
        cache_hit: bool = False,
        error_category: Optional[str] = None,
        client_ip: str = "127.0.0.1",
        timestamp: Optional[float] = None,
    ) -> str:
        metric_id = f"req_{uuid.uuid4().hex[:14]}"
        ts = timestamp if timestamp is not None else time.time()
        db.execute(
            """
            INSERT INTO request_metrics (
                id, project_id, endpoint_id, api_key_id, version, method, path,
                status_code, latency_ms, request_bytes, response_bytes, cache_hit,
                error_category, client_ip, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                metric_id,
                project_id,
                endpoint_id,
                api_key_id,
                version,
                method.upper(),
                path,
                int(status_code),
                float(latency_ms),
                int(request_bytes),
                int(response_bytes),
                1 if cache_hit else 0,
                error_category,
                client_ip,
                ts,
            ),
        )
        return metric_id

    @classmethod
    def get_summary(
        cls,
        project_id: Optional[str] = None,
        window_minutes: int = 60,
    ) -> Dict[str, Any]:
        now = time.time()
        if project_id:
            rows = db.fetch_all(
                "SELECT * FROM request_metrics WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,),
            )
        else:
            rows = db.fetch_all("SELECT * FROM request_metrics ORDER BY created_at DESC")

        total_requests = len(rows)
        latencies = sorted(float(r["latency_ms"]) for r in rows)
        status_2xx = sum(1 for r in rows if 200 <= int(r["status_code"]) < 300)
        status_4xx = sum(1 for r in rows if 400 <= int(r["status_code"]) < 500)
        status_5xx = sum(1 for r in rows if int(r["status_code"]) >= 500)
        error_count = status_4xx + status_5xx
        error_rate_pct = (
            round((error_count / total_requests) * 100.0, 2) if total_requests > 0 else 0.0
        )

        last_minute_count = sum(1 for r in rows if float(r["created_at"]) >= (now - 60))
        window_cutoff = now - (window_minutes * 60)
        window_count = sum(1 for r in rows if float(r["created_at"]) >= window_cutoff)
        avg_rpm = round(window_count / max(1, window_minutes), 2)

        # Daily usage breakdown (last 7 days)
        daily_buckets: Dict[str, int] = {}
        for r in rows:
            day_str = datetime.fromtimestamp(float(r["created_at"]), tz=timezone.utc).strftime(
                "%Y-%m-%d"
            )
            daily_buckets[day_str] = daily_buckets.get(day_str, 0) + 1
        daily_usage = [
            {"date": d, "requests": c} for d, c in sorted(daily_buckets.items())[-14:]
        ]

        # Per-minute RPM buckets (last 15 minutes)
        rpm_buckets: List[Dict[str, Any]] = []
        current_min_epoch = int(now // 60) * 60
        for i in range(14, -1, -1):
            b_start = current_min_epoch - (i * 60)
            b_end = b_start + 60
            label = datetime.fromtimestamp(b_start, tz=timezone.utc).strftime("%H:%M")
            cnt = sum(1 for r in rows if b_start <= float(r["created_at"]) < b_end)
            rpm_buckets.append({"minute": label, "requests": cnt})

        latency_stats = {
            "min_ms": round(latencies[0], 2) if latencies else 0.0,
            "avg_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
            "p50_ms": compute_percentile(latencies, 50),
            "p90_ms": compute_percentile(latencies, 90),
            "p95_ms": compute_percentile(latencies, 95),
            "p99_ms": compute_percentile(latencies, 99),
            "max_ms": round(latencies[-1], 2) if latencies else 0.0,
        }

        return {
            "project_id": project_id or "all",
            "total_requests": total_requests,
            "current_rpm": last_minute_count,
            "average_rpm": avg_rpm,
            "status_breakdown": {
                "2xx": status_2xx,
                "4xx": status_4xx,
                "5xx": status_5xx,
            },
            "error_count": error_count,
            "error_rate_percent": error_rate_pct,
            "latency_percentiles": latency_stats,
            "rpm_series": rpm_buckets,
            "daily_usage": daily_usage,
            "cache": response_cache.stats(),
            "generated_at": now,
        }

    @classmethod
    def get_endpoint_performance(
        cls, project_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if project_id:
            rows = db.fetch_all(
                "SELECT * FROM request_metrics WHERE project_id = ?", (project_id,)
            )
        else:
            rows = db.fetch_all("SELECT * FROM request_metrics")

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            key = f"{r['method']} /gateway/{r['version']}{r['path']}"
            grouped.setdefault(key, []).append(r)

        results: List[Dict[str, Any]] = []
        for route_key, items in grouped.items():
            lats = sorted(float(x["latency_ms"]) for x in items)
            errs = sum(1 for x in items if int(x["status_code"]) >= 400)
            hits = sum(1 for x in items if int(x["cache_hit"]) == 1)
            total = len(items)
            sample = items[0]
            results.append(
                {
                    "route": route_key,
                    "version": sample["version"],
                    "method": sample["method"],
                    "path": sample["path"],
                    "requests": total,
                    "error_count": errs,
                    "error_rate_percent": round((errs / total) * 100.0, 2) if total else 0.0,
                    "cache_hit_rate_percent": round((hits / total) * 100.0, 2) if total else 0.0,
                    "p50_ms": compute_percentile(lats, 50),
                    "p95_ms": compute_percentile(lats, 95),
                    "p99_ms": compute_percentile(lats, 99),
                    "avg_ms": round(sum(lats) / total, 2) if total else 0.0,
                }
            )
        results.sort(key=lambda x: x["requests"], reverse=True)
        return results

    @classmethod
    def generate_svg_chart(cls, project_id: Optional[str] = None) -> str:
        """Generate an embeddable SVG operational chart for RPM & Latency Percentiles."""
        summary = cls.get_summary(project_id=project_id)
        lat = summary["latency_percentiles"]
        bars = [
            ("p50", lat["p50_ms"], "#38bdf8"),
            ("p90", lat["p90_ms"], "#818cf8"),
            ("p95", lat["p95_ms"], "#f59e0b"),
            ("p99", lat["p99_ms"], "#f43f5e"),
        ]
        max_val = max([b[1] for b in bars] + [10.0])
        rects = []
        for idx, (label, val, color) in enumerate(bars):
            x = 70 + idx * 120
            bar_h = int((val / max_val) * 130)
            y = 170 - bar_h
            rects.append(
                f'<rect x="{x}" y="{y}" width="64" height="{max(4, bar_h)}" rx="6" fill="{color}" />'
                f'<text x="{x + 32}" y="{y - 8}" fill="#e2e8f0" font-family="sans-serif" font-size="12" text-anchor="middle">{val}ms</text>'
                f'<text x="{x + 32}" y="192" fill="#94a3b8" font-family="sans-serif" font-size="12" text-anchor="middle">{label}</text>'
            )
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 560 220" width="100%" height="220">'
            '<rect width="560" height="220" rx="12" fill="#0f172a"/>'
            '<text x="24" y="28" fill="#f8fafc" font-family="sans-serif" font-size="14" font-weight="bold">'
            f'API-Hub-Pro Latency Percentiles (Total Req: {summary["total_requests"]}, Err: {summary["error_rate_percent"]}%)'
            "</text>"
            + "".join(rects)
            + "</svg>"
        )

    @classmethod
    def export_report(
        cls, fmt: str = "json", project_id: Optional[str] = None
    ) -> Tuple[str, str]:
        """Export analytics report in JSON or CSV format. Returns (content_type, content_str)."""
        summary = cls.get_summary(project_id=project_id)
        endpoints = cls.get_endpoint_performance(project_id=project_id)
        if fmt.lower() == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(
                [
                    "route",
                    "version",
                    "method",
                    "path",
                    "requests",
                    "error_count",
                    "error_rate_percent",
                    "cache_hit_rate_percent",
                    "p50_ms",
                    "p95_ms",
                    "p99_ms",
                    "avg_ms",
                ]
            )
            for ep in endpoints:
                writer.writerow(
                    [
                        ep["route"],
                        ep["version"],
                        ep["method"],
                        ep["path"],
                        ep["requests"],
                        ep["error_count"],
                        ep["error_rate_percent"],
                        ep["cache_hit_rate_percent"],
                        ep["p50_ms"],
                        ep["p95_ms"],
                        ep["p99_ms"],
                        ep["avg_ms"],
                    ]
                )
            return "text/csv", buf.getvalue()

        report = {
            "report_type": "apihub_pro_analytics_report",
            "version": "2.0.0",
            "summary": summary,
            "endpoint_performance": endpoints,
        }
        return "application/json", json.dumps(report, indent=2)


analytics_engine = AnalyticsEngine()
