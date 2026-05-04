<div align="center">

<pre>
███████╗██████╗  █████╗ ███████╗
██╔════╝██╔══██╗██╔══██╗██╔════╝
███████╗██████╔╝███████║█████╗  
╚════██║██╔═══╝ ██╔══██║██╔══╝  
███████║██║     ██║  ██║██║     
╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     
</pre>

**Smart Pentesting Automation Framework**

*Scan. Analyze. Exploit. Remediate — Automatically.*

<br>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Async](https://img.shields.io/badge/Engine-Asyncio-00C7B7?style=flat-square&logo=python&logoColor=white)](https://docs.python.org/3/library/asyncio.html)
[![MongoDB](https://img.shields.io/badge/Database-MongoDB-47A248?style=flat-square&logo=mongodb&logoColor=white)](https://mongodb.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)
[![Stars](https://img.shields.io/github/stars/geevarghesekthomas84-sys/spaf?style=flat-square&logo=github&color=gold)](https://github.com/geevarghesekthomas84-sys/spaf/stargazers)

<br>

**— AI Providers —**

[![Gemini](https://img.shields.io/badge/Google%20Gemini-2.0%20Flash-8E75B2?style=flat-square&logo=googlegemini&logoColor=white)](https://ai.google.dev)
[![Claude](https://img.shields.io/badge/Anthropic%20Claude-3.5%20Sonnet-D97757?style=flat-square&logo=anthropic&logoColor=white)](https://anthropic.com)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20%7C%20Streaming-black?style=flat-square&logo=ollama&logoColor=white)](https://ollama.ai)
[![LM Studio](https://img.shields.io/badge/LM%20Studio-Local%20%7C%20Streaming-FFD21E?style=flat-square&logo=huggingface&logoColor=black)](https://lmstudio.ai)
[![Shodan](https://img.shields.io/badge/Shodan-Passive%20Intel-FF0000?style=flat-square&logo=shodan&logoColor=white)](https://shodan.io)

</div>

---

## 📌 What is SPAF?

**SPAF** is a professional, asynchronous offensive security framework that acts as an **AI-powered Red Team brain**. It goes beyond traditional scanners by automatically transforming vulnerability data into weaponized attack intelligence.

- 🎯 Run **multi-vector scans** against any target
- 🧠 **AI threat analysis** runs automatically after every scan (Google, Claude, Ollama, LM Studio)
- 🚀 **Auto-generate Proof-of-Concept exploit scripts** in Python
- 🛠️ Receive **production-ready remediation code** in Ansible, Terraform, or Bash
- 🕵️ Operate with **full anonymity** via TOR, proxy rotation, and fingerprint randomization
- ⏱️ **24/7 shadow monitoring** with intelligent alerting
- 📡 **Passive Shodan intelligence** — open ports & org info without touching the target
- 📊 **Export findings** to CSV/JSON for client deliverables
- 🔍 **Diff two scans** — instantly see what changed (new/fixed/unchanged)
- 🐳 **Docker-ready** — one command to spin up the full stack

---

## ✨ Core Feature Set

<table width="100%">
<tr>
<td valign="top" width="50%">

### 🧠 AI Intelligence Suite
Connect to any leading AI model for Red Team-grade analysis. After **every scan**, SPAF automatically sends findings to your configured AI and generates a module-specific intelligence report covering attack paths, exploitation techniques, CVE correlation, and actionable remediation — printed directly in the terminal.

**Supported providers (all work with every command):**
| Provider | Type | Shortcut |
|---|---|---|
| Google Gemini 2.0 Flash | ☁️ Remote | `spaf gemini` |
| Anthropic Claude 3.5 | ☁️ Remote | `spaf claude` |
| Ollama (local) | 💻 Streaming | `spaf ollama` |
| LM Studio (local) | 💻 Streaming | `spaf lmstudio` |

> Local providers (**Ollama / LM Studio**) stream tokens in real-time as they are generated.  
> Add `--no-ai` to any scan command to skip AI analysis.

</td>
<td valign="top" width="50%">

### 🕵️ Stealth & OpsSec Engine
Every single request is wrapped in configurable operational security layers.

- Native **TOR** integration (`socks5://`)
- Rotating **SOCKS5/HTTP proxy** chains
- Dynamic **User-Agent** fingerprint rotation
- Per-module **concurrency** & request delay controls

### 📡 Passive Shodan Intel
Set `SHODAN_API_KEY` in `.env` to enrich every recon scan with passive Shodan data — open ports, org, ISP, and country — **without sending a single packet to the target**.

</td>
</tr>
<tr>
<td valign="top" width="50%">

### 🔍 Reconnaissance Module
Build a complete attack surface map before firing a single payload.

- Passive subdomain enumeration via `crt.sh`
- Active DNS brute-forcing (12+ common prefixes)
- DNS Record audit: SPF, DMARC, AXFR zone transfer
- WHOIS registrant email exposure analysis
- **Shodan passive IP intelligence** (optional)

</td>
<td valign="top" width="50%">

### 🌐 Web Security Auditor
Deep-dive assessment of web application security posture.

- Security headers: CSP, HSTS, XFO, X-Content-Type
- Cookie flags: `Secure`, `HttpOnly`, `SameSite`
- Sensitive path probing: `.env`, `.git`, admin portals
- TLS/SSL: protocol versions, certificate expiry

</td>
</tr>
<tr>
<td valign="top" width="50%">

### 🔌 Network Intelligence
High-speed, configurable port scanning with automated threat correlation.

- **Nmap** integration with `light`, `normal`, `aggressive` profiles
- **RustScan** turbo-discovery (async TCP) → hand-off to Nmap for deep analysis
- Service version detection & OS fingerprinting
- Automated CVE mapping via **NIST NVD API** (rate-limited, supports API key)

</td>
<td valign="top" width="50%">

### 📊 Reporting & Export
Generate executive-grade deliverables.

- 🌑 **Dark-mode HTML Dashboard** with severity-ranked findings
- 📄 **Structured JSON** output for pipelines
- 📋 **CSV Export** (`spaf export`) for client-ready spreadsheets
- 🔍 **Scan Diff** (`spaf diff`) — compare any two scans visually

</td>
</tr>
</table>

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/geevarghesekthomas84-sys/spaf.git
cd spaf

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Install shell tab-completion (optional but recommended)
spaf --install-completion

# Run the interactive setup wizard
spaf setup
```

> **Requirements:** Python 3.9+, [Nmap](https://nmap.org), MongoDB (local or remote)
>
> **Optional:** [RustScan](https://github.com/RustScan/RustScan) for ultra-fast port discovery  
> **Optional:** [Shodan CLI](https://pypi.org/project/shodan/) (`pip install shodan`) for passive recon

---

## 🐳 Docker Deployment

The fastest way to get running — no manual setup of MongoDB or Python environment needed.

```bash
# 1. Start MongoDB + SPAF in one command
docker-compose up -d

# 2. Run any scan
docker-compose run spaf recon target.com
docker-compose run spaf scan target.com --scanner rustscan --ports 1-65535

# 3. Drop into interactive AI shell
docker-compose run spaf shell

# Override the entire command
docker-compose run spaf export target.com --format csv
```

> **Note:** `docker-compose.yml` uses `network_mode: host` so Nmap/RustScan can reach real targets.  
> `.env` is automatically mounted from the project root — add your API keys there.

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and configure your providers:

```bash
# ─── AI Provider (choose one) ────────────────────────────────────
AI_PROVIDER=google            # google | claude | ollama | lmstudio

# Remote providers
GOOGLE_API_KEY=your_key
ANTHROPIC_API_KEY=your_key

# Model overrides (optional — defaults shown)
GOOGLE_MODEL=gemini-2.0-flash
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022

# Local providers
OLLAMA_URL=http://localhost:11434/v1
OLLAMA_MODEL=llama3.2             # optional, auto-detected
LM_STUDIO_URL=http://localhost:1234/v1
LM_STUDIO_MODEL=your-model        # optional, auto-detected from loaded model

# ─── APIs ────────────────────────────────────────────────────────
NIST_API_KEY=your_key             # free: https://nvd.nist.gov/developers/request-an-api-key
SHODAN_API_KEY=your_key           # free: https://account.shodan.io/register

# ─── Stealth / OpsSec ────────────────────────────────────────────
USE_TOR=false
PROXY_FILE=./proxies.txt
RANDOM_USER_AGENT=true

# ─── Database ────────────────────────────────────────────────────
SPAF_MONGO_URI=mongodb://localhost:27017
```

---

## 💻 Usage

> 📖 **Full command reference with all flags and examples → [COMMANDS.md](COMMANDS.md)**

```bash
# ─── Reconnaissance ──────────────────────────────────────────────
spaf recon target.com                                # Recon + AI + Shodan (if key set)
spaf recon target.com --passive --no-ai              # Passive OSINT only

# ─── Network Scanning ────────────────────────────────────────────
spaf scan target.com                                 # Nmap + AI analysis
spaf scan target.com --scanner rustscan --ports 1-65535  # RustScan → Nmap
spaf scan target.com --intensity aggressive          # Deep scan (-sV -sC -O -A)

# ─── Web Security ────────────────────────────────────────────────
spaf webscan https://target.com                      # Full web audit + AI
spaf crawl https://target.com --depth 3              # Spider + AI

# ─── AI Provider Shortcuts (all context-safe) ────────────────────
spaf test-ai                                         # Health check + status table
spaf chat "How do I bypass a WAF?"                   # Configured provider
spaf gemini "Explain CVE-2024-1234"                  # Google Gemini
spaf claude "Write an Ansible remediation task"      # Anthropic Claude
spaf ollama "List SMB exploitation paths"            # Ollama — live streaming
spaf lmstudio "Analyze these HTTP headers"           # LM Studio — live streaming

# ─── AI Analysis on past scans ───────────────────────────────────
spaf ai <scan_id>                                    # Re-analyze (no re-scan)
spaf ai <scan_id> --provider ollama                  # Use Ollama for this run

# ─── Exploit & Remediation ───────────────────────────────────────
spaf poc <finding_id>                                # Generate Python exploit script
spaf poc <finding_id> --output exploit.py
spaf remediate <finding_id> --format ansible         # Fix code (ansible/terraform/bash)

# ─── Operations ──────────────────────────────────────────────────
spaf export target.com --format csv                  # Export findings to CSV
spaf export target.com --format json                 # Export findings to JSON
spaf diff <scan_id_1> <scan_id_2>                    # Compare two scans
spaf scope show                                      # View engagement scope
spaf scope add target.com                            # Add to scope
spaf scope remove target.com                         # Remove from scope
spaf watch target.com --interval 3600 --module webscan   # 24/7 monitoring
spaf report target.com --format html                 # Premium HTML report
spaf history                                         # Past scan records
spaf shell                                           # Interactive AI shell
spaf update                                          # Update SPAF to latest
```

---

## 🤖 AI Provider Setup

### Quick Comparison

| Provider | Type | Model | Privacy | Streaming | Best For |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **Google Gemini** | ☁️ Remote | `gemini-2.0-flash` | Low | ❌ | Fastest, largest context |
| **Anthropic Claude** | ☁️ Remote | `claude-3-5-sonnet-20241022` | Low | ❌ | Report writing, remediation |
| **Ollama** | 💻 Local | auto-detected | ✅ High | ✅ Live | Air-gapped, unlimited usage |
| **LM Studio** | 💻 Local | auto-detected | ✅ High | ✅ Live | Private, no data leaves host |

### Ollama Setup

```bash
# 1. Install Ollama → https://ollama.com
# 2. Pull a model
ollama pull llama3.2
ollama pull qwen2.5-coder   # great for exploit/remediation code

# 3. Set in .env
AI_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434/v1   # default, change if remote
OLLAMA_MODEL=llama3.2                  # optional — auto-detected if not set

# 4. Test connection
spaf test-ai

# 5. Use shortcut (tokens stream in real-time)
spaf ollama "List exploitation paths for open SMB ports"
```

### LM Studio Setup

```bash
# 1. Download LM Studio → https://lmstudio.ai
# 2. Load any GGUF model in the app
# 3. Go to: Local Server tab → Start Server

# 4. Set in .env
AI_PROVIDER=lmstudio
LM_STUDIO_URL=http://localhost:1234/v1  # default
LM_STUDIO_MODEL=your-model-name         # optional — auto-detected from loaded model

# 5. Test connection
spaf test-ai

# 6. Use shortcut (tokens stream in real-time)
spaf lmstudio "Analyze these HTTP headers for security risks"
```

> **All AI name variants accepted:** `lmstudio`, `lm-studio`, `lm_studio` all work as `AI_PROVIDER` values.

---

## 📡 Shodan Integration

Enrich every `spaf recon` scan with **passive Shodan intelligence** — open ports, org, ISP, and country — without sending any packets to the target.

```bash
# 1. Get a free API key → https://account.shodan.io/register
# 2. Add to .env
SHODAN_API_KEY=your_api_key

# 3. Install the Shodan library
pip install shodan

# 4. Run recon — Shodan data is fetched automatically
spaf recon target.com
```

---

## 🔍 Scan Diff & Export

```bash
# View scan history to get IDs
spaf history

# Compare two scans — see what's new, fixed, or unchanged
spaf diff <older_scan_id> <newer_scan_id>

# Export all findings for a target to CSV (for clients)
spaf export target.com --format csv
spaf export target.com --format json --output /tmp/findings.json
```

---

## 🗂️ Engagement Scope

```bash
# Initialise scope (creates scope.json in current directory)
spaf scope add target.com
spaf scope add 10.0.0.0/24

# View current scope
spaf scope show

# Remove a target
spaf scope remove 10.0.0.0/24

# Use a custom scope file
spaf scope show --file engagement_scope.json
```

---

## 📁 Project Structure

```
spaf/
├── spaf/
│   ├── cli/          # Typer CLI — all commands
│   ├── core/         # Async engine & BaseModule
│   ├── modules/      # recon, network, webscan, crawler
│   ├── utils/        # AI orchestrator, proxy, risk, validator, logger
│   ├── database/     # MongoDB async driver (Motor) with full indexes
│   └── reports/      # HTML & JSON report generator
├── tests/            # Pytest test suite
├── plugins/          # Drop-in custom scan modules
├── Dockerfile        # Python 3.12-slim + nmap
├── docker-compose.yml # MongoDB 7 + SPAF with healthcheck
├── scope.json        # Engagement scope (auto-created)
├── COMMANDS.md       # Full command reference
└── .env.example      # Configuration template
```

---

## 🔒 Stealth & OpsSec

| Variable | Description |
|---|---|
| `USE_TOR=true` | Route all requests through TOR (`socks5://127.0.0.1:9050`) |
| `PROXY_FILE=./proxies.txt` | Rotating SOCKS5/HTTP proxy chain file |
| `RANDOM_USER_AGENT=true` | Randomise browser User-Agent per request |
| `NIST_API_KEY=<key>` | NIST NVD API key (10× CVE lookup rate — free signup) |
| `SHODAN_API_KEY=<key>` | Passive Shodan intel in recon (free tier available) |

---

## ⚠️ Legal Disclaimer

> This tool is intended **strictly** for authorized security testing, research, and educational purposes only. The developer assumes **no liability** for any misuse or damage caused. Always obtain **explicit written permission** from the target organization before conducting any security tests.

---

<div align="center">

Built with 🔥 by **[geevarghesekthomas84-sys](https://github.com/geevarghesekthomas84-sys)**

⭐ If you find SPAF useful, please consider starring the repository — it helps a lot!

</div>
