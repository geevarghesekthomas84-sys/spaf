# SPAF threat model & risk classification

SPAF is offensive-security tooling: used correctly it tests systems its operator
is **authorized** to test; used incorrectly it can cause harm. This document
states what SPAF defends against, what it deliberately does not, and the risk
class of each workflow — so operators and contributors reason about blast radius
on purpose, not by accident.

> **Authorized testing only.** Scope enforcement, authorization signing, and the
> audit trail are safety controls, **not** authorization. You are responsible for
> having written permission for every target you point SPAF at.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Engagement scope & authorizations | Define what may be touched; tampering = unauthorized scanning |
| API keys / provider tokens / signing key | Access to the service and to AI providers |
| Scan findings & reports | Sensitive details about a client's weaknesses |
| Audit trail | The accountability record of what was done |
| The host SPAF runs on | Runs network tools and (optionally) AI-generated content |

## 2. Trust boundaries

```
operator ─▶ CLI ───┐
HTTP client ─▶ API ─┼─▶ service engine ─▶ modules ─▶ TARGET (untrusted output)
MCP host ─▶ MCP ────┘        │
                             ├─▶ AI provider (untrusted output)
                             └─▶ storage / audit (trusted sink)
```

Everything a **target** or an **AI provider** returns is untrusted input. It may
be logged, stored, and shown — it is never executed as a command and never
treated as an instruction.

## 3. What SPAF defends against (controls)

| Threat | Control | Where |
|---|---|---|
| Scanning out-of-scope hosts | Engagement-scope enforcement (fail-closed when scope set) | `utils/scope.py`, `service` |
| Accidental mass / internet-wide scan | Overly-broad-target rejection (wildcards, huge CIDR) | `utils/validator.py` |
| Unauthorized active testing | Signed engagement authorizations (HMAC, expiry) | `workspaces/authorization.py` |
| Unauthenticated API access | API-key auth on every non-public endpoint | `api/`, `workspaces/principals.py` |
| Privilege misuse | RBAC roles (viewer/operator/lead) | `workspaces/` |
| Request flooding / external-service abuse | Per-principal rate limiting (429) | `api/ratelimit.py` |
| Command injection | `subprocess` **arg lists** only (never `shell=True`) + denylist | `modules/`, `utils/safety.py` |
| Prompt-injection via target/AI output | Output sanitization, defanging, never-execute policy | `utils/safety.py` |
| Secret leakage in logs | Redaction filter on all log sinks | `utils/logger.py` |
| Malformed input | URL/host/CIDR/payload validation at the boundary | `utils/validator.py`, API validators |
| Supply-chain CVEs | Trivy + pip-audit + CycloneDX SBOM in CI | `.github/workflows/security.yml` |
| Blast radius of the API container | Non-root, read-only FS, cap_drop, TLS gateway | `deploy/` |

## 4. Out of scope (explicit non-goals)

- SPAF does **not** grant authorization or verify you have it.
- It does not sandbox the external recon binaries it runs (`nmap`, `nuclei`, …) —
  run it on a host you control, ideally the hardened container.
- It does not defend against a malicious operator with a valid lead key.
- AI providers see the prompts you send; use local models (Ollama/LM Studio) when
  engagement data must not leave the host.

## 5. Risk classification per workflow

| Workflow | Touches target? | Risk | Notes / safeguards |
|---|---|---|---|
| `scope` / `engagements` | No | **Low** | Config only; lead-gated writes, audited |
| `recon` (passive) | Indirect (OSINT/DNS) | **Low–Med** | Passive by default; scope-gated |
| `recon` (active) / `toolkit` | Yes | **Med** | Scope-gated, audited; rate-limited over API |
| `webscan` / `crawl` | Yes | **Med** | HTTP against target; scope-gated |
| `scan` (network/nmap) | Yes | **Med–High** | Port/CVE mapping; validated, arg-list exec, scope-gated |
| `agent` (dry-run) | No | **Low** | Planning only; no target contact |
| `agent` (active) | Yes | **High** | Requires in-scope + (when signing on) valid authorization; audited |
| nuclei DAST / aggressive | Yes | **High** | Opt-in only; most intrusive path |

**Mock mode** (`SPAF_MOCK=1` or `--mock` / `options.mock`) drops every workflow to
**Low**: the pipeline runs end-to-end with synthetic findings and no target is
contacted — use it for development, demos, and CI.

## 6. Reporting

Security issues: see [`SECURITY.md`](../SECURITY.md). Hardening a deployment:
see [`SECURITY_HARDENING.md`](../SECURITY_HARDENING.md).
