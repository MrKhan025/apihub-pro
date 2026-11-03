#!/usr/bin/env python3
"""
Primary entrypoint for API-Hub-Pro (`apihub-pro`).
Usage:
  python main.py serve --host 0.0.0.0 --port 8000
  python main.py migrate
  python main.py seed-demo
  python main.py security-audit
  python main.py export-report --format csv
"""

import sys
from apihub.cli import main

if __name__ == "__main__":
    sys.exit(main())
