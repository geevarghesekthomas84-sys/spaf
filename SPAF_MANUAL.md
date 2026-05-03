# 🛡️ SPAF: Technical Architecture & Operations Manual
**Offensive Security Automation Framework**

---

## 🏗️ System Architecture

SPAF is engineered with a high-concurrency, asynchronous architecture designed for scalability and stealth.

### 1. The Core Engine (`spaf.core.engine`)
The heart of SPAF is an `asyncio`-driven orchestration layer. 
- **BaseModule**: Abstract class defining the interface for all scanning modules.
- **ScanEngine**: Manages module execution lifecycle, progress tracking with `Rich`, and persistence hooks.
- **Resource Management**: Implements proxy-aware `aiohttp` sessions with automated header rotation.

### 2. AI Intelligence Layer (`spaf.utils.ai`)
The framework leverages Large Language Models (LLMs) to transform raw data into offensive intelligence.
- **Multi-Provider Support**: Native integration with Google Gemini (Pro), Anthropic (Claude 3), and OpenAI-compatible local APIs (Ollama, LM Studio).
- **Contextual Analysis**: Findings are injected into structured prompts to generate bypass strategies and exploitation paths.

### 3. Stealth & OpsSec (`spaf.utils.proxy`)
Operational Security is baked into every request:
- **Proxy Rotation**: Supports SOCKS5 (TOR) and HTTP proxy lists.
- **Fingerprint Randomization**: Dynamic User-Agent switching to evade WAF/IPS signature-based detection.
- **Rate Limiting**: Per-module semaphore-based concurrency control and configurable request delays.

---

## 🛠️ Advanced Module Reference

### 🔍 Reconnaissance (`spaf recon`)
Aggregates passive and active data sources to map the target's attack surface.
- **crt.sh Integration**: Extracts subdomains from Certificate Transparency logs.
- **DNS Analysis**: Performs AXFR zone transfer attempts, SPF/DMARC audit, and record enumeration.
- **WHOIS Redaction Check**: Identifies exposed registrant data.

### 📡 Network Auditing (`spaf scan`)
High-speed service discovery and vulnerability correlation.
- **Nmap Wrapper**: Executes optimized Nmap profiles (`light`, `normal`, `aggressive`).
- **NVD API Integration**: Correlates service versions with the NIST National Vulnerability Database for real-time CVE mapping.

### 🌐 Web Assessment (`spaf webscan`)
Deep analysis of web application security posture.
- **Security Header Audit**: Checks for CSP, HSTS, XFO, etc.
- **Sensitive Path Probing**: Concurrent discovery of `.env`, `.git`, and administrative interfaces.
- **TLS/SSL Evaluation**: Detects deprecated protocols (TLS 1.0/1.1) and expiring certificates.

---

## 🐚 The Interactive Shell

The SPAF shell provides a stateful environment for security researchers:
- **`analyze <scan_id>`**: Triggers a Red Team deep-dive into a specific scan's findings.
- **`chat <query>`**: Real-time consultation with the AI provider for exploit payload crafting or bypass advice.

---

## 📊 Operational Deployment

### Docker Deployment
```bash
docker-compose up -d  # Starts MongoDB and SPAF environment
docker exec -it spaf shell
```

### Database Management
SPAF utilizes **MongoDB** for persistence. All findings are deduplicated based on target, vulnerability type, and scan ID to ensure high-quality, non-redundant reporting.

---

## 📜 Legal & Ethical Usage
Usage of SPAF for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

**Developed by gg**
