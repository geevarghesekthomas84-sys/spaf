# SPAF deploy

Hardened stack: a **Caddy** gateway (TLS + security headers) in front of the
**SPAF API**, with optional MongoDB.

```bash
cp .env.example .env          # set SPAF_API_KEYS and SPAF_DOMAIN
docker compose up -d --build  # gateway + API (SQLite)
curl -k https://localhost/health
```

Add MongoDB: `docker compose --profile mongo up -d --build`.

Full hardening, mTLS, rate-limiting, secrets (sops), and the authorized-egress
note are in [`../SECURITY_HARDENING.md`](../SECURITY_HARDENING.md).
