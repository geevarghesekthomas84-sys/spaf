# SPAF Command Reference

> **Smart Pentesting Automation Framework** — AI-Augmented Offensive Security  
> Every scan command automatically runs AI threat analysis after completion.  
> Add `--no-ai` to any command to skip AI analysis.

---

## 🔍 Scanning Commands

### `spaf recon <target>` — Domain Reconnaissance
Passive and active reconnaissance against a domain: subdomain enumeration, DNS audit, WHOIS analysis, zone-transfer attempts.

```bash
spaf recon target.com                          # Passive + active recon + AI analysis
spaf recon target.com --passive                # Passive only (stealthy, OSINT only)
spaf recon target.com --no-ai                  # Skip AI analysis
spaf recon target.com --output results.json    # Save findings to JSON
spaf recon target.com --delay 1.5 --concurrency 3   # Stealth mode (slow + low concurrency)
```

| Flag | Default | Description |
|---|---|---|
| `--passive` / `--active` | `--passive` | Passive OSINT only vs. active brute-force |
| `--output <file>` | — | Save results as JSON |
| `--delay <seconds>` | `0.0` | Delay between DNS requests |
| `--concurrency <n>` | `5` | Max concurrent subdomain resolutions |
| `--no-ai` | off | Skip AI analysis after scan |
| `--no-db` | off | Run without MongoDB logging |

---

### `spaf scan <target>` — Network Port Scan
High-speed port scanning using **Nmap** or **RustScan**, with service detection, OS fingerprinting, and automated CVE lookups via NIST NVD.

```bash
spaf scan target.com                                       # Nmap — standard scan + AI
spaf scan target.com --intensity aggressive                # Nmap — deep scan (-sV -sC -O -A)
spaf scan target.com --ports 1-65535                       # Full port range
spaf scan target.com --scanner rustscan --ports 1-65535    # RustScan → Nmap pipeline
spaf scan target.com --scanner rustscan --ulimit 8000      # RustScan — increase throughput
spaf scan target.com --no-ai                               # Skip AI analysis
```

| Flag | Default | Description |
|---|---|---|
| `--scanner` | `nmap` | Scanner engine: `nmap` \| `rustscan` |
| `--ports` | `1-1024` | Port range (e.g., `1-65535`) |
| `--intensity` | `normal` | Nmap depth: `light` \| `normal` \| `aggressive` |
| `--ulimit` | `5000` | RustScan: open file descriptor limit |
| `--batch-size` | `2500` | RustScan: ports probed per batch |
| `--no-ai` | off | Skip AI analysis after scan |
| `--no-db` | off | Run without MongoDB logging |

> **How RustScan + Nmap works:** RustScan does async TCP mass-connect to find open ports, then hands them to Nmap for full service/OS/CVE detection.

---

### `spaf webscan <url>` — Web Security Audit
Deep web application security assessment: security headers, cookie flags, TLS/certificate checks, sensitive path probing, CORS, server disclosure.

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
| `--no-ai` | off | Skip AI analysis after scan |
| `--no-db` | off | Run without MongoDB logging |

---

### `spaf crawl <url>` — Web Application Spider
Recursively crawls a web application, discovers endpoints, forms, and flags sensitive keywords in page source.

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
| `--no-ai` | off | Skip AI analysis after scan |
| `--no-db` | off | Run without MongoDB logging |

---

## 🤖 AI Commands

### `spaf ai <scan_id>` — Re-Analyze a Past Scan
Re-runs the module-specific AI analysis on any previous scan's findings **without re-scanning** the target. Auto-detects the module type.

```bash
spaf ai <scan_id>                              # Re-analyze with auto-detected module
spaf ai <scan_id> --module network             # Force network prompt
spaf ai <scan_id> --provider ollama            # Use Ollama for this call only
spaf ai <scan_id> --provider lmstudio          # Use LM Studio for this call only
```

| Flag | Default | Description |
|---|---|---|
| `--module` | auto | Module prompt: `recon` \| `network` \| `webscan` \| `crawler` |
| `--provider` | `.env` | Override AI provider for this call only |

---

### `spaf analyze` — Full AI Threat Report
Generic AI analysis that can analyze findings by scan ID or from a JSON file.

```bash
spaf analyze --id <scan_id>                    # Analyze scan from database
spaf analyze --file findings.json             # Analyze from local JSON file
```

---

### `spaf chat <query>` — Direct AI Consultation
Free-form chat with the configured AI provider for security research questions.

```bash
spaf chat "How do I bypass a WAF?"
spaf chat "Write a Python PoC for CVE-2024-xxxx"
```

---

### `spaf gemini <query>` — Gemini Shortcut
Dedicated shortcut to query Google Gemini regardless of `AI_PROVIDER` setting.

```bash
spaf gemini "Explain CVE-2024-1234"
```

---

### `spaf poc <finding_id>` — Generate Exploit Script
Generates a standalone Python Proof-of-Concept exploit script for a specific finding.

```bash
spaf poc <finding_id>
spaf poc <finding_id> --output exploit.py      # Save to file
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

### `spaf test-ai` — AI Provider Health Check
Tests the configured AI provider's connectivity and prints a health report.

```bash
spaf test-ai
```

**Output:**
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

## 📊 Reporting & Operations

### `spaf report <target>` — Generate Report

```bash
spaf report target.com --format html           # Dark-mode HTML dashboard
spaf report target.com --format json           # Structured JSON export
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `html` | Output format: `html` \| `json` |

---

### `spaf watch <target>` — Shadow Scan (24/7 Monitoring)
Continuously re-runs a module on a schedule. AI alerts when new findings are detected.

```bash
spaf watch target.com                          # Recon every hour (default)
spaf watch target.com --interval 1800          # Every 30 minutes
spaf watch target.com --module webscan         # Monitor web security posture
spaf watch target.com --module network         # Monitor open ports
spaf watch target.com --no-ai                  # No AI alert summaries
spaf watch target.com --no-db                  # No database logging
```

| Flag | Default | Description |
|---|---|---|
| `--interval <seconds>` | `3600` | Seconds between scans |
| `--module` | `recon` | Module: `recon` \| `webscan` \| `network` \| `crawl` |
| `--no-ai` | off | Skip AI analysis + alert summaries |
| `--no-db` | off | Run without MongoDB logging |

---

### `spaf history` — View Past Scans

```bash
spaf history                                   # Show recent scan history
```

---

### `spaf shell` — Interactive AI Shell
Interactive terminal with built-in AI commands.

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
spaf setup                                     # Interactive first-time setup
```

---

### `spaf login` — Cloud Authentication

```bash
spaf login                                     # Authenticate with SPAF cloud
```

---

## ⚙️ Global Options

| Flag | Description |
|---|---|
| `--no-ai` | Skip automatic AI analysis after any scan |
| `--no-db` | Run in offline mode (no MongoDB required) |
| `--help` | Show detailed help for any command |

---

## 🌍 AI Providers — `.env` Configuration

| Provider | `AI_PROVIDER` | Required Key | Model Var |
|---|---|---|---|
| Google Gemini | `google` | `GOOGLE_API_KEY` | `GOOGLE_MODEL` (default: `gemini-2.0-flash`) |
| Anthropic Claude | `claude` | `ANTHROPIC_API_KEY` | `ANTHROPIC_MODEL` |
| Ollama (local) | `ollama` | — | `OLLAMA_MODEL` (auto-detected) |
| LM Studio (local) | `lmstudio` | — | `LM_STUDIO_MODEL` (auto-detected) |

> **Ollama name variants all work:** `ollama` | `lmstudio` | `lm-studio` | `lm_studio`

**Quick local setup:**
```bash
# Ollama
AI_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434/v1
OLLAMA_MODEL=llama3.2           # optional, auto-detected

# LM Studio
AI_PROVIDER=lmstudio
LM_STUDIO_URL=http://localhost:1234/v1
LM_STUDIO_MODEL=your-model     # optional, auto-detected
```

---

## 🔒 Stealth / OpsSec (`.env`)

| Variable | Description |
|---|---|
| `USE_TOR=true` | Route all requests through TOR (`socks5://127.0.0.1:9050`) |
| `PROXY_FILE=./proxies.txt` | Rotating SOCKS5/HTTP proxy chain file |
| `RANDOM_USER_AGENT=true` | Randomise browser User-Agent per request |
| `NIST_API_KEY=<key>` | NIST NVD API key (10× CVE lookup rate — free signup) |

---

## 💡 Examples — Common Workflows

```bash
# Full pentest workflow
spaf recon target.com
spaf webscan https://target.com
spaf scan target.com --intensity aggressive --scanner rustscan --ports 1-65535
spaf crawl https://target.com --depth 3

# Offline / air-gapped (Ollama, no DB)
AI_PROVIDER=ollama spaf scan target.com --no-db

# Re-analyze an old scan with a different AI
spaf ai abc123scan --provider claude

# 24/7 web monitoring with AI alerts
spaf watch target.com --module webscan --interval 3600

# Generate deliverables
spaf report target.com --format html
spaf poc <finding_id> --output exploit.py
spaf remediate <finding_id> --format ansible
```
