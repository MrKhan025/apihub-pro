# Contributing to APIHub-Pro (`apihub-pro`)

Thank you for contributing to **APIHub-Pro**! Follow these guidelines to keep the platform clean, secure, and 100% backward compatible.

## 1. Development Workflow

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/MrKhan025/apihub-pro.git
   cd apihub-pro
   ```
2. Create a virtual environment and install development dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements-dev.txt
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 2. Quality & Security Gate Checklist

Before opening a Pull Request, run all verification checks locally:

```bash
# 1. Database migrations & demo workspace seed
PYTHONPATH=. python3 main.py migrate
PYTHONPATH=. python3 main.py seed-demo

# 2. Full unit, integration & security test suite (20 tests)
PYTHONPATH=. python3 -m unittest discover -s tests -v

# 3. Automated security auditor & HMAC-SHA256 audit chain check
PYTHONPATH=. python3 main.py security-audit

# 4. Bandit static security scan
bandit -q -ll -s B101,B104,B303,B310,B608 -r apihub
```

## 3. Coding Standards

- Never commit `.env` files, private keys, or static credentials.
- Preserve backward compatibility for all `/api/v1/*` and `/api/v2/*` routes when extending `/api/v3/*`.
- Document every new route in `docs/API.md` and add unit/integration tests in `tests/`.
