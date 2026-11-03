# Deployment & Operations Guide — API-Hub-Pro (`apihub-pro`) v2.0

## 1. Local & Termux Quick Start

### Linux / macOS / Windows
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
python3 main.py migrate
python3 main.py seed-demo
python3 main.py serve --host 0.0.0.0 --port 8000
```

### Android Termux Setup
```bash
bash scripts/termux-setup.sh
PYTHONPATH=. python3 main.py serve --host 127.0.0.1 --port 8000
```

---

## 2. Production Docker Compose Deployment (PostgreSQL 16 + Redis 7)

1. Copy `.env.example` to `.env` and set strong values for `POSTGRES_PASSWORD`, `APIHUB_SECRET_KEY`, `APIHUB_AUDIT_HMAC_SECRET`, and `APIHUB_WEBHOOK_SECRET`.
2. Start the production stack using the `production` profile:
   ```bash
   docker compose --profile production up -d --build
   ```
3. Verify container health and migrations:
   ```bash
   curl http://localhost:8000/health
   curl http://localhost:8000/api/v2/infra/status
   ```

---

## 3. Database Migrations (Alembic)

- Apply all migrations to `head`:
  ```bash
  python3 main.py migrate --revision head
  ```
- Inspect current revision via REST:
  ```bash
  curl http://localhost:8000/api/v2/infra/status
  ```

---

## 4. Running Automated Tests & Security Audits

```bash
# Run full unit and integration test suite (compatible with both unittest and pytest)
PYTHONPATH=. python3 -m unittest discover -s tests -v

# Run automated security auditor CLI
PYTHONPATH=. python3 main.py security-audit
```
