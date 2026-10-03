# SPAF deploy

Run the SPAF API hardened, behind a **Caddy** TLS gateway. Only the gateway is
exposed to the network; the API listens on an internal network and is reached
only through Caddy. State (SQLite DB, audit logs, AI cache, engagements) lives on
the `spaf_data` volume under `/data`, so the container itself runs **read-only**.

```
          ┌─────────────┐        internal         ┌───────────────┐
  :443 ──▶│   Caddy      │ ─────────────────────▶ │  SPAF API      │
  :80  ──▶│  TLS·headers │   http://api:8000       │  (read-only,   │
          │  (opt mTLS)  │                         │   non-root)    │──▶ /data
          └─────────────┘                         └───────────────┘    volume
```

## Quick start

```bash
cd deploy
cp .env.example .env          # set SPAF_API_KEYS (and SPAF_DOMAIN for real TLS)
docker compose up -d --build  # gateway + API (SQLite, zero-setup)
curl -k https://localhost/health
```

Add MongoDB instead of SQLite:

```bash
docker compose --profile mongo up -d --build
```

## What you get

Through the gateway (replace `localhost` with your `SPAF_DOMAIN`):

| URL | Auth | What |
|---|---|---|
| `https://localhost/` | open | built-in web **dashboard** |
| `https://localhost/health`, `/version` | open | liveness / version |
| `https://localhost/metrics` | open | Prometheus metrics (aggregate only) |
| `https://localhost/docs` | open | OpenAPI explorer |
| everything else | `X-API-Key` | scans, agent, scope, engagements, audit |

## Configuration (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `SPAF_API_KEYS` | — (required) | comma-separated API keys |
| `SPAF_DOMAIN` | `localhost` | public domain for automatic Let's Encrypt TLS |
| `SPAF_ACME_EMAIL` | — | contact e-mail for real-domain ACME |
| `SPAF_DB_BACKEND` | `sqlite` | `sqlite` (zero-setup) or `mongo` (`--profile mongo`) |
| `AI_PROVIDER`, `GOOGLE_API_KEY`, `ANTHROPIC_API_KEY` | — | optional AI assessment |
| `SPAF_PRINCIPALS` | — | map keys → roles + engagements (RBAC; unset = all-access lead) |
| `SPAF_AUTH_SIGNING_KEY` | — | mint tamper-evident engagement authorizations |

Inside the container, all writable state is pinned under `/data`
(`SPAF_SQLITE_PATH`, `SPAF_AUDIT_LOG`, `SPAF_CACHE_PATH`, `SPAF_ENGAGEMENTS_DIR`),
which is the only writable path — the root filesystem is read-only.

## Hardening at a glance

- **Gateway** — automatic TLS, HSTS + security headers, request-body cap; opt-in
  **mTLS** and rate-limiting (see the Caddyfile). Drops all caps except
  `NET_BIND_SERVICE`, `no-new-privileges`.
- **API container** — non-root (uid 10001), **read-only root FS** with state only
  on the `/data` volume, `cap_drop: ALL`, `no-new-privileges`, CPU/memory limits,
  and a `/health` healthcheck.
- **Exposure** — only the gateway publishes ports (80/443); the API and Mongo are
  internal-only.

Full guide — mTLS, rate-limiting, sops+age secrets, the authorized-egress note,
and a pre-exposure checklist — in
[`../SECURITY_HARDENING.md`](../SECURITY_HARDENING.md).
