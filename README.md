
<div align="center">

```
███████╗██████╗  █████╗ ███████╗
██╔════╝██╔══██╗██╔══██╗██╔════╝
███████╗██████╔╝███████║█████╗  
╚════██║██╔═══╝ ██╔══██║██╔══╝  
███████║██║     ██║  ██║██║     
╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     
```

### Smart Pentesting Automation Framework

*Precision. Intelligence. Automation.*

---

[![License](https://img.shields.io/github/license/geevarghesekthomas84-sys/spaf?style=for-the-badge&color=0d1117&labelColor=30363d)](LICENSE)
[![Stars](https://img.shields.io/github/stars/geevarghesekthomas84-sys/spaf?style=for-the-badge&color=0d1117&labelColor=30363d&logo=github)](https://github.com/geevarghesekthomas84-sys/spaf/stargazers)
[![Python](https://img.shields.io/badge/Python-3.9%2B-0d1117?style=for-the-badge&logo=python&logoColor=3776AB&labelColor=30363d)](https://python.org)
[![Async](https://img.shields.io/badge/Async-Engine-0d1117?style=for-the-badge&logo=lightning&logoColor=F7DF1E&labelColor=30363d)](#)

---

**AI Providers**

[![Gemini](https://img.shields.io/badge/Google%20Gemini-Pro-0d1117?style=for-the-badge&logo=googlegemini&logoColor=8E75B2&labelColor=30363d)](https://ai.google.dev)
[![Claude](https://img.shields.io/badge/Anthropic%20Claude-3.5-0d1117?style=for-the-badge&logo=anthropic&logoColor=D97757&labelColor=30363d)](https://anthropic.com)
[![Ollama](https://img.shields.io/badge/Ollama-Local-0d1117?style=for-the-badge&logo=ollama&logoColor=FFFFFF&labelColor=30363d)](https://ollama.ai)
[![LM Studio](https://img.shields.io/badge/LM%20Studio-Local-0d1117?style=for-the-badge&logo=huggingface&logoColor=FFD21E&labelColor=30363d)](https://lmstudio.ai)

</div>

---

## `> OVERVIEW`

**SPAF** is an elite, AI-augmented offensive security framework built for modern red teamers and security professionals. It bridges the gap between raw vulnerability discovery and actionable exploitation intelligence — automatically.

> **SPAF doesn't just scan. It thinks.**

---

## `> CAPABILITIES`

<table>
<tr>
<td width="50%">

**🧠 AI Intelligence Suite**
- Deep-dive Red Team analysis with Gemini Pro & Claude 3.5
- Automated Proof-of-Concept (POC) exploit generation
- Tailored remediation: Ansible, Terraform, Bash

</td>
<td width="50%">

**🕵️ Shadow Operations**
- Native TOR routing for anonymous scanning
- SOCKS5/HTTP proxy chain orchestration
- Dynamic User-Agent & browser fingerprint rotation

</td>
</tr>
<tr>
<td width="50%">

**📡 Multi-Vector Reconnaissance**
- Passive: Certificate Transparency (`crt.sh`)
- Active: DNS brute-force, AXFR zone transfer attempts
- Live subdomain resolution & WHOIS email exposure

</td>
<td width="50%">

**🌐 Web Security Engine**
- Security headers audit (CSP, HSTS, XFO)
- TLS/SSL protocol & certificate analysis
- Sensitive path probing (`.env`, `.git`, admin panels)

</td>
</tr>
<tr>
<td width="50%">

**🔌 Network Intelligence**
- Nmap with `light`, `normal`, `aggressive` profiles
- Real-time CVE mapping via NIST NVD
- Service version fingerprinting

</td>
<td width="50%">

**📊 Executive Reporting**
- Premium dark-mode HTML dashboards
- Structured JSON for automated pipelines
- Severity-ranked findings with recommendations

</td>
</tr>
</table>

---

## `> INSTALLATION`

```bash
# 1. Clone the repository
git clone https://github.com/geevarghesekthomas84-sys/spaf.git && cd spaf

# 2. Set up the environment
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt && pip install -e .

# 3. Configure (interactive wizard)
spaf setup
```

> **Prerequisites:** Python 3.9+, Nmap, MongoDB

---

## `> USAGE`

```bash
# Passive & Active Reconnaissance
spaf recon target.com

# Web Application Security Audit
spaf webscan https://target.com

# Network Port Scan + CVE Mapping
spaf scan target.com --intensity aggressive

# AI-Powered Red Team Analysis
spaf analyze --id <scan_id>

# Generate Weaponized Exploit Script
spaf poc <finding_id> --output exploit.py

# Auto-generate Remediation Code
spaf remediate <finding_id> --format ansible

# Start Interactive AI Security Shell
spaf shell

# 24/7 Continuous Monitoring
spaf watch target.com --interval 3600

# Generate Premium HTML/JSON Report
spaf report target.com --format both --output-dir ./reports
```

---

## `> AI STACK`

| Provider | Mode | Model | Use Case |
| :--- | :--- | :--- | :--- |
| **Google Gemini** | Remote | Gemini 1.5 Pro | Deep analysis, POC generation |
| **Anthropic Claude** | Remote | Claude 3.5 Sonnet | Report writing, remediation |
| **Ollama** | Local | Auto-detect | Air-gapped environments |
| **LM Studio** | Local | Auto-detect | Offline / private deployments |

---

## `> STEALTH CONFIG`

Configure via `.env` for full operational control:

```bash
USE_TOR=true                         # Route all traffic via TOR
PROXY_FILE=./proxies.txt             # Rotating SOCKS5/HTTP proxies
RANDOM_USER_AGENT=true               # Dynamic browser fingerprinting
AI_PROVIDER=google                   # google | claude | ollama | lmstudio
```

---

## `> DISCLAIMER`

This tool is intended **strictly** for authorized security testing and research purposes. The developer assumes no liability for misuse. Always obtain **written consent** before testing any target.

---

<div align="center">

Developed by **[geevarghesekthomas84-sys](https://github.com/geevarghesekthomas84-sys)**

</div>
