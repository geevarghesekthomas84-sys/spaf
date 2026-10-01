# Changelog

All notable changes to SPAF are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
