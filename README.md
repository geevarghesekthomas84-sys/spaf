# 🛡️ SPAF: Smart Pentesting Automation Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![AI-Powered](https://img.shields.io/badge/AI--Powered-Google%20Gemini%20%7C%20Claude-red.svg)](#)

**SPAF** (Smart Pentesting Automation Framework) is an elite, AI-augmented offensive security framework designed for modern security researchers and red teamers. It bridges the gap between traditional vulnerability scanners and manual exploitation by providing automated intelligence, stealthy reconnaissance, and production-ready remediation.

---

## 🚀 Key Features

*   **🤖 AI-Powered Intelligence**: Deep analysis of findings using **Google Gemini**, **Claude**, or local models (**Ollama/LM Studio**).
*   **📡 Modular Scanning Engine**: High-performance asynchronous modules for Recon, Network, and Web security.
*   **🚀 Auto-POC Generator**: Instantly craft functional Python exploit scripts for identified vulnerabilities.
*   **🕵️ Stealth & OpsSec**: Integrated **TOR** support, rotating proxies, and randomized browser fingerprinting.
*   **⏱️ Shadow Scan (Monitoring)**: Continuous 24/7 target monitoring with AI-summarized alerts.
*   **🛠️ Auto-Remediation**: Generate Ansible, Terraform, and Bash code to patch security holes automatically.
*   **🐚 Interactive Security Shell**: A stateful, AI-assisted terminal for real-time security consultation.

---

## 🛠️ Installation

### 1. Prerequisites
Ensure you have **Python 3.9+** and **Nmap** installed on your system.

### 2. Clone & Setup
```bash
git clone https://github.com/gg/spaf.git
cd spaf
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### 3. Configuration
Run the interactive setup to configure your AI providers and database:
```bash
spaf setup
```
Or manually copy `.env.example` to `.env` and fill in your keys.

---

## 💻 Quick Start Guide

### 1. Comprehensive Web Audit
```bash
spaf webscan https://example.com --output results.json
```

### 2. AI Security Analysis
```bash
spaf analyze --id <scan_id>
```

### 3. Generate a Proof-of-Concept
```bash
spaf poc <finding_id> --output exploit.py
```

### 4. Continuous Shadow Monitoring
```bash
spaf watch example.com --interval 3600 --module webscan
```

### 5. Enter the AI Shell
```bash
spaf shell
```

---

## 📊 Premium Reporting
Generate beautiful, dark-themed HTML dashboards and structured JSON reports for your clients.
```bash
spaf report example.com --format html --output-dir ./reports
```

---

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an issue.

## 📜 License
Distributed under the **MIT License**. See `LICENSE` for more information.

---

**Developed with ❤️ by [gg](https://github.com/gg)**

> [!WARNING]  
> **Disclaimer**: This tool is strictly for authorized security testing and educational purposes only. Unauthorized use of this tool against targets without prior written consent is illegal and unethical.
