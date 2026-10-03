# Changelog

All notable changes to SPAF are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.14.0]

### Added
- **Staged pipeline (`spaf/pipeline/`)** — an explicit, ordered workflow:
  **discovery → validation → remediation → report**, with strict hand-offs so a
  stage receives only the previous stage's typed `StageResult` and cannot reach
  into another stage's internals. Each stage runs a fixed set of modules
  (discovery: recon/toolkit/crawl; validation: webscan/scan) through
  `run_module`, so scope, RBAC, audit, rate limiting, and mock mode all apply.
  Remediation enriches the consolidated findings with fix guidance (no target
  contact, inputs never mutated); report renders a JSON deliverable.
  - CLI: `spaf pipeline <target>` (`--mock`, `--report-dir`, `--no-db`).
  - API: `POST /pipeline` (async job, operator role, scope-gated).
  - `StageResult` / `PipelineResult` added to the JSON-Schema export.

## [1.13.0]

### Added
- **Machine-readable result schema (`spaf/service/schema.py`)** — JSON Schema for
  every result model (`Finding`, `ScanResult`, `AgentResult`, …) so downstream
  tooling validates SPAF output instead of reverse-engineering it. Exposed via
  the `spaf schema` CLI command (`--write <dir>`, `--model <name>`), an open
  `GET /schema` API endpoint, and checked-in schemas under `docs/schemas/`.
- **Architecture guide (`docs/ARCHITECTURE.md`)** — layering, request flow, the
  result contract, and the three extension seams (scan modules, AI providers,
  output consumers), plus the governance/safety seams.

## [1.12.0]

### Added — safety & hardening
- **Mock mode** (`SPAF_MOCK=1`, `--mock`, or `options.mock`) — the full
  discovery→findings pipeline runs with deterministic synthetic results and
  **no target is contacted**. Safe for development, demos, and CI.
- **Overly-broad-target rejection** (`spaf/utils/validator.py`) — wildcards
  (`*`, `0.0.0.0/0`, `::/0`), bare TLDs, and CIDRs larger than `MAX_CIDR_HOSTS`
  (/16) are refused at the input boundary, independent of engagement scope, to
  prevent accidental or abusive mass scanning.
- **Input hardening** — API `ScanRequest`/`AgentRequest` validate module names,
  targets (via `validate_scan_target`), and cap free-text payloads
  (`validate_prompt_payload`); malformed/overly-broad input → `422`.
- **Rate limiting** (`spaf/api/ratelimit.py`) — per-principal token bucket
  (`SPAF_RATE_LIMIT`/`SPAF_RATE_BURST`); excess requests → `429` and increment
  `spaf_rate_limited_total`.
- **Output/command safety** (`spaf/utils/safety.py`) — a destructive-command
  denylist (`is_dangerous_command`, `assert_safe_argv`) as defence-in-depth over
  the existing arg-list-only execution, and `sanitize_ai_text` to strip control
  characters, cap length, and defang prompt-injection markers in generated text.
- **Secret redaction in logs** (`spaf/utils/logger.py`) — a logging filter scrubs
  API keys, tokens, `Authorization`/`Bearer`, and known key formats from every
  log sink.
- **Supply-chain CI** — `pip-audit` dependency CVE scan + a CycloneDX **SBOM**
  artifact, alongside the existing Trivy scans.
- **Threat model** — `docs/THREAT_MODEL.md`: assets, trust boundaries, the
  controls above, explicit non-goals, and a per-workflow risk classification.

## [1.11.0]

### Added
- **Multi-engagement workspaces + RBAC (`spaf/workspaces/`)** — teams can run
  several concurrent engagements, isolated from each other, with role-based
  access control:
  - **Engagements** — each is an isolated workspace with its own scope file,
    audit trail, and report storage under `SPAF_ENGAGEMENTS_DIR`
    (`engagements/<id>/`). Work in one engagement cannot leak into another.
    Manage from the CLI (`spaf engagements [--create …]`) or the API
    (`GET/POST /engagements`).
  - **Roles** — `viewer` (read-only), `operator` (+ launch scans / active agent
    runs), `lead` (+ manage scope, create engagements). Principals map API keys
    to a role and a set of allowed engagements via `SPAF_PRINCIPALS` /
    `SPAF_PRINCIPALS_FILE`. **Backwards-compatible:** with no principals
    configured, existing `SPAF_API_KEYS` act as all-access leads, so RBAC is
    strictly opt-in.
  - **Signed authorizations** — an engagement can carry a tamper-evident
    HMAC-signed record of the client's go-ahead (who authorized, scope hash,
    expiry), minted only with `SPAF_AUTH_SIGNING_KEY`. When a signing key is set,
    active runs on a persisted engagement require a valid, unexpired signature.
  - **Retention policies** — per-engagement `retention_days` with a `purge_expired`
    sweep over stored reports.
  - **API**: every request carries a principal (role) and an optional
    `X-Engagement` header selecting the workspace; `GET /whoami` reports identity;
    viewers get `403` on active endpoints, out-of-engagement access gets `403`,
    unknown engagements `404`.

## [1.10.0]

### Added
- **Observability + built-in web dashboard** —
  - **Prometheus metrics (`spaf/api/metrics.py`, `GET /metrics`)** — a tiny,
    dependency-free counter registry rendered in Prometheus text format. Tracks
    `spaf_scans_started/completed/failed_total{module}`,
    `spaf_findings_total{severity}`, `spaf_agent_runs_total{mode}`, and
    `spaf_auth_failures_total`. Only aggregate labels (no target names), so the
    endpoint is safe to scrape without leaking engagement data. Left open (no key)
    for scrapers.
  - **Audit view (`GET /audit`)** — key-protected tail of the JSONL audit log for
    recent active actions.
  - **Web dashboard (`GET /` and `/dashboard`)** — a self-contained, vanilla-JS
    console (served from `spaf/api/static/dashboard.html`) matching the CLI's
    amber/steel theme: API-key connect, status/scope/tools, a run panel
    (recon/toolkit/scan/webscan/crawl/agent with dry-run), a live WebSocket event
    log, a findings table, and the audit view.
  - Auth failures now increment `spaf_auth_failures_total`.

## [1.9.0]

### Added
- **MCP client (`spaf/mcp/client.py`, `spaf mcp-tools`)** — SPAF can now *consume*
  external MCP servers. Configure them in Claude-Desktop shape
  (`mcp_servers.json` / `SPAF_MCP_SERVERS`) and list/call their tools.
- **Plugin SDK (`spaf/plugins/`, `spaf plugins`)** — third parties add scan
  modules by subclassing `PluginModule` and advertising them via the
  `spaf.modules` entry-point group (or the `@spaf_module` decorator). Registered
  modules run through the CLI/service/API/MCP; they are deliberately **not**
  added to the autonomous agent's fixed action set.

## [1.8.0]

### Added
- **Secure deployment stack (`deploy/`)** — a hardened way to run the API:
  - **Caddy gateway** fronting the API with automatic TLS, security headers
    (HSTS, nosniff, DENY, no-referrer), a request-body cap, and opt-in blocks
    for **mTLS** and rate-limiting.
  - **Hardened API image** (`deploy/Dockerfile`): multi-stage wheel build,
    **non-root** user, **read-only** root FS with state confined to `/data`,
    `cap_drop: ALL`, `no-new-privileges`, resource limits, healthcheck.
  - **docker-compose** stack (gateway + API, optional Mongo via `--profile mongo`);
    only the gateway is network-exposed.
  - **`SECURITY_HARDENING.md`** — mTLS, rate-limiting, sops+age secrets, an
    authorized-egress note, and a pre-exposure checklist.
- **CI security scanning** (`.github/workflows/security.yml`) — Trivy over the
  filesystem (deps/secrets/misconfig) and the built API image, weekly + on PRs.

## [1.7.0]

### Added
- **AI orchestration layer (`spaf/orchestration/`)** — the agent's planning and
  assessment now run through a shared orchestrator:
  - **Model router** — route tasks to specific models with fallbacks, config-driven
    (`SPAF_MODEL_PLAN` / `_ANALYZE` / `_CODEGEN` / `_DEFAULT`); unset = provider default.
  - **Response cache** — prompt→response cache (`logs/ai_cache.db`, `SPAF_CACHE=off`
    to disable) cuts cost/latency and makes runs replayable.
  - **Run budget** — bound calls/characters/time per run
    (`SPAF_BUDGET_CALLS` / `_CHARS` / `_SECONDS`) so an autonomous loop can't run away.
  - **Fallback chain** — on a provider/model error the next model in the chain is tried.
  - New `ai_orchestrator.complete(..., model=…)` for per-call model override.

## [1.6.0]

### Added
- **HTTP API (`spaf serve`, `spaf[api]` extra)** — FastAPI REST + WebSocket over
  the service layer. Async job model: `POST /scans` and `POST /agent` return a
  job id, progress streams over `WS /ws/jobs/{id}`, and `GET /jobs/{id}` returns
  the typed result. Plus `/scope`, `/tools`, `/scans/recent`, `/findings/{id}`,
  and OpenAPI docs at `/docs`. Secure by default: API-key auth on every endpoint
  except `/health` and `/version` (a key is generated and logged if none is set),
  and active scans are scope-gated (out-of-scope → 403). Binds `127.0.0.1` by
  default.

### Fixed
- `EventBus`: subscribing after `close()` no longer hangs (WebSocket connecting
  to a just-finished job).

## [1.5.0]

### Added
- **Service layer (`spaf/service/`)** — a typed, UI-free facade (`SpafService`)
  with Pydantic models, an async `EventBus`, and an append-only **audit log** for
  every active action. Runs modules **headlessly** (no stdout) so it is safe
  under the MCP stdio transport; scope is enforced centrally.
- **MCP server (`spaf mcp`, `spaf[mcp]` extra)** — exposes SPAF as MCP tools
  (`recon`, `toolkit`, `scan`, `webscan`, `crawl`, `agent_run`, `scope_show`,
  `scope_add`, `tools_status`) plus `spaf://scope` / `spaf://tools` resources and
  an `assess_target` prompt, over stdio for Claude Desktop and other MCP hosts.
  Safety: scope enforced inside every tool with no model-exposed bypass;
  `agent_run` is plan-only unless `dry_run=false`; no raw-command tool; output is
  shaped/capped for context. `pydantic>=2` added to core.

### Notes
- The MCP server is optional — install with `pip install "spaf[mcp]"`.
- First slice of the v2 platform roadmap (`docs/ROADMAP_V2.md`).

> **1.5.0 is the first release since 1.1.0**, so it also ships everything from
> 1.2–1.4: the recon toolkit, engagement scope, the autonomous agent, the SQLite
> backend + redesigned setup, `--version`, and the premium CLI redesign.

## [1.4.0]

### Changed
- **Premium CLI redesign.** A single design system (`spaf/utils/ui.py`): one
  signature accent (molten amber `#E0A82E`) on a steel monochrome base, with
  severity colors reserved strictly for findings. New one-line brand lockup
  (`◇ SPAF · red-team automation · vX · ● status`) reused across commands, a
  single-tone amber wordmark, hairline tables, soft panels, and letter-spaced
  section rules. Banner, scan init/summary, AI-analysis panel, setup wizard,
  the agent plan/assessment, `spaf tools`, and every module's results table now
  share the same look. Per-scan output shows only the compact lockup (the full
  wordmark is reserved for top-level commands).

## [1.3.0]

### Added
- **Autonomous agent (`spaf agent <target>`)** — the configured AI plans an
  ordered sequence of SPAF modules (recon → toolkit → webscan → crawl → scan),
  the agent runs them on the host, accumulates findings, and writes a single
  consolidated AI assessment. The AI only chooses *which* built-in modules run
  (never arbitrary commands). Flags: `--goal`, `--dry-run`, `--yes`,
  `--aggressive`, `--scope-file`/`--ignore-scope`, `--output`, `--no-ai`,
  `--no-db`. Active steps are scope-gated and require confirmation; `--no-ai`
  falls back to a default playbook.

## [1.2.0]

### Added
- **`--version` / `-V` flag** and the running version is now shown in the banner
  and the setup wizard header.
- **Redesigned `spaf setup`** — a guided, sectioned wizard (AI → Database →
  Stealth) with styled panels and a configuration summary table.
- **Local database provisioning from setup** — SQLite is initialized in place
  (no server), and MongoDB can be auto-provisioned via Docker (`mongo:7`
  container), with an offer to fall back to SQLite if it can't be reached.

## [1.1.0]

### Added
- **SQLite storage backend** — a zero-setup offline fallback for MongoDB.
  Select it with `SPAF_DB_BACKEND=sqlite` (file path via `SPAF_SQLITE_PATH`);
  SPAF then runs with no database server required. New `spaf.database.sqlite`
  backend and a `spaf.database` selector (`from spaf.database import db`).
- **Expanded `spaf setup` wizard** — now prompts for the LM Studio / Ollama
  server URL and model (blank = auto-detect), the database backend
  (mongodb/sqlite) with the matching settings, and the MongoDB database name.

### Fixed
- `.env` was discovered relative to the installed package instead of the
  directory `spaf` is run from, so a project-local `.env` loaded inconsistently;
  it is now loaded from the current working directory (`find_dotenv(usecwd=True)`).

## [1.0.0]

### Added
- **PyPI release workflow** — pushing a `vX.Y.Z` tag builds and publishes to PyPI
  via Trusted Publishing (OIDC, no token secret). Enriched package metadata
  (authors, license, classifiers, URLs) for the PyPI listing.
- **nuclei URL-corpus chaining** — the toolkit now feeds crawled + historical
  URLs (in-scope only) into nuclei alongside probed hosts, with a new
  `--nuclei-dast` flag for fuzzing templates and a URL cap.
- **Structured reports** — HTML reports gain a severity-distribution chart, a
  per-module breakdown, and an optional embedded AI analysis (`spaf report
  --with-ai`); JSON reports gain `summary`, `by_module`, and `ai_analysis`.
- **`spaf tools --install`** — installs the Go-based recon suite via `go install`
  (with `--force` to reinstall all).
- Demo walkthrough script (`scripts/demo.sh`) + recording recipe (`docs/demo.md`)
  and a README demo section.

### Fixed
- **Security:** HTML reports interpolated attacker-controlled finding data
  (server headers, titles, URLs) into the page without escaping — an
  HTML/script-injection vector in generated reports. All fields are now escaped,
  and the AI markdown renderer escapes before formatting.

### Added (earlier this cycle)
- **External recon toolkit** (`spaf toolkit`) — a chained pipeline wrapping
  `subfinder`, `assetfinder`, `dnsx`, `httpx`, `katana`, `hakrawler`,
  `waybackurls`, `gau`, `ffuf`, and `nuclei`. Each stage feeds the next and every
  binary is optional (missing tools are skipped gracefully).
- **`spaf tools`** — shows install status and sources for the recon toolkit.
- **Engagement-scope enforcement** — the toolkit refuses out-of-scope entry
  targets and drops out-of-scope discovered hosts before any active stage
  (`--scope-file`, `--ignore-scope`). New reusable `spaf/utils/scope.py`.
- Continuous integration (GitHub Actions): tests on Python 3.11/3.12, ruff lint,
  and a wheel build that verifies all subpackages are packaged.
- Project-health files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`,
  and GitHub issue/PR templates.
- Test suite expanded from 3 to 26 tests (scope, toolkit parsers, network args).

### Fixed
- **Security:** network scans invoked `nmap`/`rustscan` via a shell with the
  unvalidated target interpolated into the command string (shell-injection
  vector). Switched to argument-list `exec` and added target validation to
  `spaf scan`.
- **CLI:** a duplicate `test-ai` command silently overrode the detailed
  health-check version; removed the duplicate.
- **Packaging:** added missing `__init__.py` files and switched to setuptools
  package discovery so wheel builds ship every subpackage (previously only the
  top-level package was included).
- **Dependencies:** added `beautifulsoup4` (imported by the crawler) to core
  dependencies; a PyPI install previously crashed on `spaf crawl`. AI providers
  and Shodan are now optional extras (`ai`, `intel`).
- `.gitignore` no longer ignores the `spaf/reports` package directory.
- Documented `SHODAN_API_KEY` and `NIST_API_KEY` in `.env.example`.
