"""
Command-Line Interface for API-Hub-Pro (apihub-pro).
Supports:
- `serve`         : Launch uvicorn API Gateway & Dashboard server
- `migrate`       : Run Alembic database schema migrations
- `seed-demo`     : Seed sample users, projects, dynamic APIs, webhooks & marketplace listings
- `security-audit`: Run automated security auditing and verify HMAC-SHA256 audit chain
- `export-report` : Export analytics summary and endpoint performance in JSON or CSV format
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from apihub import __version__
from apihub.analytics import analytics_engine
from apihub.config import settings
from apihub.database import db
from apihub.security import security_manager
from apihub.seed import seed_demo_workspace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apihub",
        description=f"API-Hub-Pro (apihub-pro) v{__version__} — Enterprise API Gateway CLI",
    )
    parser.add_argument("--version", action="version", version=f"apihub-pro {__version__}")
    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="Start the API-Hub-Pro gateway server")
    serve_p.add_argument("--host", default=settings.host, help="Bind host (default: 0.0.0.0)")
    serve_p.add_argument("--port", type=int, default=settings.port, help="Bind port (default: 8000)")
    serve_p.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    serve_p.add_argument(
        "--seed",
        action="store_true",
        default=True,
        help="Automatically seed demo workspace on startup (default: True)",
    )

    mig_p = sub.add_parser("migrate", help="Run Alembic database migrations")
    mig_p.add_argument("--revision", default="head", help="Target revision (default: head)")

    sub.add_parser("seed-demo", help="Initialize demo projects, dynamic endpoints, and marketplace")

    sub.add_parser("security-audit", help="Run automated security audit and verify audit log chain")

    exp_p = sub.add_parser("export-report", help="Export operational analytics report")
    exp_p.add_argument("--format", choices=["json", "csv"], default="json")
    exp_p.add_argument("--output", help="Optional file path to save the exported report")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cmd = args.command or "serve"
    if cmd == "migrate":
        result = db.run_migrations(target_revision=args.revision)
        print(json.dumps(result, indent=2))
        return 0

    if cmd == "seed-demo":
        result = seed_demo_workspace()
        print(json.dumps(result, indent=2))
        return 0

    if cmd == "security-audit":
        report = security_manager.run_automated_security_audit()
        print(json.dumps(report, indent=2))
        return 0 if report["audit_chain_integrity"]["valid"] else 1

    if cmd == "export-report":
        _, content = analytics_engine.export_report(fmt=args.format)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(content)
            print(f"Exported {args.format.upper()} report to {args.output}")
        else:
            print(content)
        return 0

    if cmd == "serve":
        import uvicorn

        db.run_migrations("head")
        if getattr(args, "seed", True):
            seed_demo_workspace()
        uvicorn.run(
            "apihub.api:app",
            host=getattr(args, "host", settings.host),
            port=getattr(args, "port", settings.port),
            reload=getattr(args, "reload", False),
        )
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
