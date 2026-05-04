# SPAF Command Reference

> **Smart Pentesting Automation Framework** — AI-Augmented Offensive Security  
> Every scan command automatically runs AI threat analysis after completion.  
> Add `--no-ai` to any command to skip. Add `--no-db` to run without MongoDB.

---

## 🗂️ Table of Contents

- [Scanning Commands](#-scanning-commands)
- [AI Commands](#-ai-commands)
- [Reporting & Operations](#-reporting--operations)
- [Engagement Scope](#-engagement-scope)
- [Global Options](#-global-options)
- [AI Provider Config](#-ai-providers--env-configuration)
- [Stealth / OpsSec](#-stealth--opsec-env)
- [Common Workflows](#-common-workflows)

---

## 🔍 Scanning Commands

### `spaf recon <target>` — Domain Reconnaissance

Passive and active reconnaissance: subdomain enumeration, DNS audit, WHOIS, zone-transfer attempts, and **passive Shodan intelligence** (if `SHODAN_API_KEY` is set).

```bash
spaf recon target.com                          # Full recon + AI + Shodan (if key set)
spaf recon target.com --passive                # Passive OSINT only (stealthy)
spaf recon target.com --no-ai                  # Skip AI analysis
spaf recon target.com --output results.json    # Save findings to JSON
spaf recon target.com --delay 1.5 --concurrency 3   # Slow + stealthy
```

| Flag | Default | Description |
|---|---|---|
| `--passive` / `--active` | passive | Passive OSINT only vs. active DNS brute-force |
| `--output <file>` | — | Save results as JSON |
| `--delay <seconds>` | `0.0` | Delay between DNS requests |
| `--concurrency <n>` | `5` | Max concurrent subdomain resolutions |
| `--no-ai` | off | Skip AI analysis after scan |
| `--no-db` | off | Run without MongoDB logging |

---

### `spaf scan <target>` — Network Port Scan

High-speed port scanning using **Nmap** or **RustScan**, with service detection, OS fingerprinting, and automated CVE lookups via NIST NVD.

```bash
spaf scan target.com                                       # Nmap standard scan + AI
spaf scan target.com --intensity aggressive                # Deep scan (-sV -sC -O -A)
spaf scan target.com --ports 1-65535                       # Full port range
spaf scan target.com --scanner rustscan --ports 1-65535    # RustScan → Nmap pipeline
spaf scan target.com --scanner rustscan --ulimit 8000      # Increase RustScan throughput
spaf scan target.com --no-ai --output network.json        # Offline, save output
```

| Flag | Default | Description |
|---|---|---|
| `--scanner` | `nmap` | Scanner engine: `nmap` \| `rustscan` |
| `--ports` | `1-1024` | Port range (e.g., `1-65535`) |
| `--intensity` | `normal` | Nmap depth: `light` \| `normal` \| `aggressive` |
| `--ulimit` | `5000` | RustScan: open file descriptor limit |
| `--batch-size` | `2500` | RustScan: ports probed per batch |
| `--output <file>` | — | Save results as JSON |
| `--no-ai` | off | Skip AI analysis after scan |
| `--no-db` | off | Run without MongoDB logging |

> **RustScan + Nmap pipeline:** RustScan does async TCP mass-connect to find open ports, then hands them to Nmap for full service/OS/CVE detection.

---

### `spaf webscan <url>` — Web Security Audit

Security headers, cookie flags, TLS/certificate checks, sensitive path probing, CORS, server disclosure.

```bash
spaf webscan https://target.com                # Full web audit + AI analysis
spaf webscan https://target.com --headers-only # Headers only (fast)
spaf webscan https://target.com --no-ai        # Skip AI analysis
spaf webscan https://target.com --output web.json
```

| Flag | Default | Description |
|---|---|---|
| `--headers-only` | off | Only check HTTP security headers |
| `--output <file>` | — | Save results as JSON |
| `--delay <seconds>` | `0.0` | Delay between path probe requests |
| `--concurrency <n>` | `5` | Max concurrent path probes |
| `--no-ai` | off | Skip AI analysis |
| `--no-db` | off | Run without MongoDB logging |

---

### `spaf crawl <url>` — Web Application Spider

Recursively crawls a web application, discovers endpoints, forms, and flags sensitive keywords.

```bash
spaf crawl https://target.com                  # Default crawl (depth 2, 50 pages)
spaf crawl https://target.com --depth 4        # Deeper crawl
spaf crawl https://target.com --max-pages 200  # Crawl more pages
spaf crawl https://target.com --no-ai          # Skip AI analysis
```

| Flag | Default | Description |
|---|---|---|
| `--depth <n>` | `2` | Maximum crawl depth |
| `--max-pages <n>` | `50` | Maximum pages to crawl |
| `--output <file>` | — | Save results as JSON |
| `--no-ai` | off | Skip AI analysis |
| `--no-db` | off | Run without MongoDB logging |

---

## 🤖 AI Commands

### `spaf test-ai` — AI Provider Health Check

Tests the configured AI provider's connectivity and prints a health report table.

```bash
spaf test-ai
```

**Output example:**
```
┌──────────────────────────────────┐
│     AI Provider Health Check     │
├──────────────┬───────────────────┤
│ Provider     │ OLLAMA            │
│ Model        │ llama3.2          │
│ Status       │ ✅ OK             │
│ Response     │ OK                │
└──────────────┴───────────────────┘
```

---

### `spaf chat <query>` — Direct AI Consultation

Free-form chat with the **configured** AI provider.

```bash
spaf chat "How do I bypass a WAF?"
spaf chat "Write a Python PoC for CVE-2024-xxxx"
```

---

### `spaf gemini <query>` — Google Gemini Shortcut

Queries **Google Gemini** regardless of `AI_PROVIDER` setting.

```bash
spaf gemini "Explain CVE-2024-1234"
spaf gemini "Write an Nmap scan script for internal networks"
```

---

### `spaf claude <query>` — Anthropic Claude Shortcut

Queries **Anthropic Claude** regardless of `AI_PROVIDER` setting.

```bash
spaf claude "Write an Ansible remediation task for missing HSTS"
spaf claude "Summarize this pentest report in executive language"
```

---

### `spaf ollama <query>` — Ollama Shortcut *(streaming)*

Queries your **locally running Ollama** model. Tokens stream to the terminal in real-time.

```bash
spaf ollama "List exploitation paths for open SMB ports"
spaf ollama "Generate a Python reverse shell"
```

> **Requires:** `ollama serve` running locally (or `OLLAMA_URL` pointing to remote).

---

### `spaf lmstudio <query>` — LM Studio Shortcut *(streaming)*

Queries the **model currently loaded in LM Studio**. Tokens stream in real-time.

```bash
spaf lmstudio "Analyze these HTTP headers for security risks"
spaf lmstudio "Summarize OWASP Top 10 attack techniques"
```

> **Requires:** LM Studio → Local Server tab → Start Server.

---

### `spaf ai <scan_id>` — Re-Analyze a Past Scan

Re-runs AI analysis on any previous scan's findings **without re-scanning** the target.

```bash
spaf ai <scan_id>                              # Re-analyze (module auto-detected)
spaf ai <scan_id> --module network             # Force network prompt template
spaf ai <scan_id> --provider ollama            # Use Ollama for this call only
spaf ai <scan_id> --provider lmstudio          # Use LM Studio for this call only
spaf ai <scan_id> --provider claude            # Use Claude for this call only
```

| Flag | Default | Description |
|---|---|---|
| `--module` | auto | Prompt template: `recon` \| `network` \| `webscan` \| `crawler` |
| `--provider` | `.env` | Override AI provider for this call only |

---

### `spaf analyze` — Full AI Threat Report

Generic AI analysis by scan ID or local JSON file.

```bash
spaf analyze --id <scan_id>
spaf analyze --file findings.json
```

---

### `spaf poc <finding_id>` — Generate Exploit Script

Generates a standalone Python Proof-of-Concept exploit script.

```bash
spaf poc <finding_id>
spaf poc <finding_id> --output exploit.py
```

---

### `spaf remediate <finding_id>` — Generate Fix Code

Generates production-ready remediation code for a specific finding.

```bash
spaf remediate <finding_id>                    # Default: Ansible
spaf remediate <finding_id> --format terraform
spaf remediate <finding_id> --format bash
```

| Flag | Default | Values | Description |
|---|---|---|---|
| `--format` | `ansible` | `ansible` \| `terraform` \| `bash` | Output format |

---

## 📊 Reporting & Operations

### `spaf export <target>` — Export Findings

Exports all deduplicated findings for a target from MongoDB to CSV or JSON.

```bash
spaf export target.com                         # Default: CSV
spaf export target.com --format csv            # Explicit CSV (client spreadsheets)
spaf export target.com --format json           # JSON (pipeline integration)
spaf export target.com --format csv --output /tmp/client_report.csv
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `csv` | Output format: `csv` \| `json` |
| `--output <file>` | `<target>_findings.<ext>` | Custom output file path |

---

### `spaf diff <scan_id_1> <scan_id_2>` — Compare Scans

Compares two scans and shows what's new, fixed, and unchanged.

```bash
spaf history                                   # Get scan IDs first
spaf diff <older_scan_id> <newer_scan_id>
```

**Output:**
```
Scan Diff  2026-05-01 10:00 → 2026-05-04 14:30
Target: target.com

┌─ 🆕 New Findings (3) ──────┐    ┌─ ✅ Fixed / Resolved (2) ──┐
│ missing_hsts               │    │ exposed_git_repo           │
│ cors_misconfiguration      │    │ cookie_no_secure_flag      │
│ server_version_disclosure  │    └────────────────────────────┘
└────────────────────────────┘

Unchanged: 5 findings
```

---

### `spaf report <target>` — Generate HTML/JSON Report

```bash
spaf report target.com --format html           # Dark-mode HTML dashboard
spaf report target.com --format json           # Structured JSON export
spaf report target.com --format both           # Both simultaneously
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `html` | Output: `html` \| `json` \| `both` |

---

### `spaf watch <target>` — Shadow Scan (24/7 Monitoring)

Continuously re-runs a module on a schedule. AI alerts when new findings are detected.

```bash
spaf watch target.com                              # Recon every hour (default)
spaf watch target.com --interval 1800              # Every 30 minutes
spaf watch target.com --module webscan             # Monitor web security posture
spaf watch target.com --module network             # Monitor open ports
spaf watch target.com --no-ai                      # Monitoring only, no AI summaries
spaf watch target.com --no-db                      # No database logging
```

| Flag | Default | Description |
|---|---|---|
| `--interval <seconds>` | `3600` | Seconds between scans |
| `--module` | `recon` | Module to run: `recon` \| `webscan` \| `network` \| `crawl` |
| `--no-ai` | off | Skip AI alert summaries |
| `--no-db` | off | Run without MongoDB logging |

---

### `spaf history` — View Past Scans

```bash
spaf history                                   # Show 20 most recent scans
spaf history target.com                        # Filter by target
spaf history --limit 50                        # Show more results
```

---

### `spaf update` — Update SPAF

```bash
spaf update                                    # pip install --upgrade spaf
```

---

### `spaf shell` — Interactive AI Shell

```bash
spaf shell
```

**Shell commands:**
| Command | Description |
|---|---|
| `chat <query>` | Talk to the configured AI |
| `analyze <scan_id>` | Run AI analysis on a past scan |
| `exit` / `quit` | Exit the shell |

---

### `spaf setup` — Configuration Wizard

```bash
spaf setup
```

---

### `spaf login` — Cloud Authentication

```bash
spaf login
```

---

## 🗂️ Engagement Scope

Manage which targets are in-scope for your engagement. Persisted to `scope.json`.

```bash
spaf scope show                                # View current scope table
spaf scope add target.com                      # Add to in-scope
spaf scope add 10.0.0.0/24                     # CIDR ranges work too
spaf scope remove target.com                   # Remove from scope
spaf scope show --file engagement.json         # Use a custom scope file
```

| Argument | Description |
|---|---|
| `show` | Display scope as a rich table |
| `add <value>` | Add domain/IP/CIDR to in-scope list |
| `remove <value>` | Remove from in-scope list |
| `--file <path>` | Custom scope file (default: `scope.json`) |

---

## ⚙️ Global Options

| Flag | Description |
|---|---|
| `--no-ai` | Skip automatic AI analysis after any scan |
| `--no-db` | Run in offline mode (no MongoDB required) |
| `--install-completion` | Install shell tab-completion (bash/zsh/fish/PowerShell) |
| `--show-completion` | Show the completion script for your shell |
| `--help` | Show detailed help for any command |

---

## 🌍 AI Providers — `.env` Configuration

| Provider | `AI_PROVIDER` | Required Key | Model Var | Streaming |
|---|---|---|---|---|
| Google Gemini | `google` | `GOOGLE_API_KEY` | `GOOGLE_MODEL` (default: `gemini-2.0-flash`) | ❌ |
| Anthropic Claude | `claude` | `ANTHROPIC_API_KEY` | `ANTHROPIC_MODEL` | ❌ |
| Ollama (local) | `ollama` | — | `OLLAMA_MODEL` (auto-detected) | ✅ |
| LM Studio (local) | `lmstudio` | — | `LM_STUDIO_MODEL` (auto-detected) | ✅ |

> **Name variants all work:** `lmstudio` \| `lm-studio` \| `lm_studio`

**Quick local setup:**
```bash
# Ollama
AI_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434/v1
OLLAMA_MODEL=llama3.2           # optional, auto-detected

# LM Studio
AI_PROVIDER=lmstudio
LM_STUDIO_URL=http://localhost:1234/v1
LM_STUDIO_MODEL=your-model      # optional, auto-detected
```

---

## 🔒 Stealth / OpsSec (`.env`)

| Variable | Description |
|---|---|
| `USE_TOR=true` | Route all requests through TOR (`socks5://127.0.0.1:9050`) |
| `PROXY_FILE=./proxies.txt` | Rotating SOCKS5/HTTP proxy chain file |
| `RANDOM_USER_AGENT=true` | Randomise browser User-Agent per request |
| `NIST_API_KEY=<key>` | NIST NVD API key (10× CVE lookup rate — free signup) |
| `SHODAN_API_KEY=<key>` | Passive Shodan recon in `spaf recon` (free tier available) |

---

## 💡 Common Workflows

```bash
# ── Full pentest engagement ───────────────────────────────────────
spaf scope add target.com
spaf recon target.com
spaf webscan https://target.com
spaf scan target.com --intensity aggressive --scanner rustscan --ports 1-65535
spaf crawl https://target.com --depth 3
spaf report target.com --format html
spaf export target.com --format csv          # Client deliverable

# ── Offline / air-gapped (Ollama, no DB) ─────────────────────────
AI_PROVIDER=ollama spaf scan target.com --no-db

# ── Re-analyze an old scan with a different AI ───────────────────
spaf ai <scan_id> --provider claude

# ── Compare weekly scans to see what changed ─────────────────────
spaf diff <last_week_scan_id> <today_scan_id>

# ── 24/7 web monitoring with AI alerts ───────────────────────────
spaf watch target.com --module webscan --interval 3600

# ── Generate exploit + fix for a finding ─────────────────────────
spaf history                                 # find finding ID
spaf poc <finding_id> --output exploit.py
spaf remediate <finding_id> --format ansible

# ── Docker quick-start ────────────────────────────────────────────
docker-compose up -d
docker-compose run spaf recon target.com
docker-compose run spaf shell
```
