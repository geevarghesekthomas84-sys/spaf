# SPAF — Secure Deployment & Hardening

How to run SPAF's API (and MCP) as a hardened service behind a reverse-proxy
gateway. The `deploy/` directory contains a ready-to-run stack.

> **Authorized testing only.** SPAF runs active scanners. Deploy it only where
> you are authorized to operate, keep the engagement scope tight, and protect
> the API — anyone with a key can launch in-scope scans.

---

## Quick start

```bash
cd deploy
cp .env.example .env            # set SPAF_API_KEYS (long random), SPAF_DOMAIN
docker compose up -d --build    # gateway + API (SQLite, zero-setup)

# health through the gateway (localhost uses an internal-CA cert → -k in dev)
curl -k https://localhost/health
```

- Only the **gateway** (Caddy) is exposed (80/443). The **API** listens on an
  internal network and is reachable only through Caddy.
- The API is **scope-gated** and **key-authenticated** — see the main README.

Add MongoDB instead of SQLite:

```bash
docker compose --profile mongo up -d --build
```

---

## What's hardened

**Gateway (Caddy)**
- Automatic TLS (Let's Encrypt for a real `SPAF_DOMAIN`, internal CA for localhost).
- Security headers: HSTS, `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `-Server`.
- Request-body size cap. `cap_drop: ALL` (+ only `NET_BIND_SERVICE`),
  `no-new-privileges`.

**API container**
- Built as a wheel in a multi-stage image; runs as a **non-root** user (uid 10001).
- **Read-only root filesystem**; all writable state confined to the `/data`
  volume; `/tmp` is tmpfs.
- `cap_drop: ALL`, `no-new-privileges`, CPU/memory limits.
- API-key auth on every endpoint except `/health` and `/version`; active scans
  return 403 when out of scope; every active action is written to
  `/data/logs/audit.jsonl`.

**CI**
- `.github/workflows/security.yml` runs Trivy over the filesystem (deps, secrets,
  misconfig) and over the built API image, weekly and on every PR.

---

## mTLS (mutual TLS)

Require a client certificate signed by your engagement CA so only issued clients
reach the gateway:

1. Put your CA at `deploy/certs/ca.pem`.
2. In `docker-compose.yml`, uncomment the `./certs:/certs:ro` volume on `gateway`.
3. In `Caddyfile`, uncomment the `tls { client_auth … }` block.
4. `docker compose up -d`.

## Rate limiting

Caddy's core image has no rate-limiter. Build a Caddy image with the
[caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) plugin (xcaddy),
then uncomment the `rate_limit` block in the `Caddyfile`.

---

## Secrets (sops + age)

Never commit real keys. Encrypt the deploy env with
[sops](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age):

```bash
age-keygen -o age.key                      # keep this private
export SOPS_AGE_RECIPIENTS=$(grep -o 'age1[0-9a-z]*' age.key)
sops --encrypt --age "$SOPS_AGE_RECIPIENTS" .env > .env.enc   # commit .env.enc

# at deploy time:
sops --decrypt .env.enc > .env && docker compose up -d && shred -u .env
```

`.gitignore` already excludes `.env`. Commit only `.env.enc`.

---

## Authorized egress routing (redirector) — opt-in, not included

For sanctioned engagements that require routing tool traffic through a controlled
egress point (a redirector), run a **separate, access-controlled forward proxy**
you operate, and point SPAF at it with the existing stealth settings
(`PROXY_FILE` / `USE_TOR` / `TOR_PROXY`). This is deliberately **not** shipped as
a compose service: an open redirector is dual-use and must be stood up only with
explicit written authorization for the specific engagement, locked to the
engagement scope, access-controlled, and torn down afterwards. SPAF enforces its
engagement scope regardless of egress path.

---

## Checklist before exposing publicly

- [ ] `SPAF_API_KEYS` set to long random value(s); not the example.
- [ ] `SPAF_DOMAIN` + `SPAF_ACME_EMAIL` set (real TLS, not the localhost cert).
- [ ] Engagement scope defined (`scope.json`) — out-of-scope is refused.
- [ ] mTLS enabled if the API should be client-cert-only.
- [ ] Secrets encrypted with sops; no plaintext keys committed.
- [ ] Trivy scan reviewed; base images up to date.
- [ ] You are authorized to scan every in-scope target.
