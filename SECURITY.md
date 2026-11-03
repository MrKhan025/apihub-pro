# Security Policy & Architecture — API-Hub-Pro (`apihub-pro`)

## Security Controls Implemented in v2.0

1. **Zero Hardcoded Credentials:** All secrets (`APIHUB_SECRET_KEY`, `APIHUB_AUDIT_HMAC_SECRET`, `APIHUB_WEBHOOK_SECRET`, `DATABASE_URL`) load from environment variables. `.env` is excluded via `.gitignore`.
2. **Password & MFA Security:** Passwords use `PBKDF2-HMAC-SHA256` (120,000 iterations) with per-user cryptographic salts and constant-time digest verification. Accounts support **RFC 6238 TOTP Multi-Factor Authentication** and 6 single-use recovery backup codes.
3. **Brute-Force Throttling:** Login attempts are rate-limited per IP and per account, automatically locking accounts after `LOGIN_MAX_ATTEMPTS` failed attempts.
4. **API Key Hashing & Grace-Period Rotation:** Raw API keys (`ahp_live_...`) are shown only once on creation or rotation and stored as `SHA-256` digests. Rotating a key issues a new key immediately while allowing the previous key to remain valid in `rotated_grace` status until `grace_period_until`.
5. **Request Size Limits & Abuse Prevention:** Middleware blocks oversized payloads (`413 Payload Too Large`) and inspects paths, queries, and bodies for SQL injection, XSS, and path traversal payloads (`400 Bad Request`).
6. **Tamper-Evident Audit Ledger:** Every security event in `audit_logs` is cryptographically chained (`prev_hash` -> `entry_hash`) using `HMAC-SHA256` and verified via `GET /api/v2/security/verify-chain` or `python3 main.py security-audit`.
