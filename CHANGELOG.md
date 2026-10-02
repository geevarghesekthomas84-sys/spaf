# Changelog

All notable changes to SPAF are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
