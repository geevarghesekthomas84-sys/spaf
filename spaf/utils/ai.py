import os
import json
import asyncio
from typing import List, Optional, Dict, Any

# ── Google GenAI (new SDK) ────────────────────────────────────────────────────
try:
    from google import genai as google_genai
    from google.genai import types as genai_types
except ImportError:
    google_genai = None
    genai_types  = None

# ── Anthropic ─────────────────────────────────────────────────────────────────
try:
    import anthropic
except ImportError:
    anthropic = None

# ── OpenAI-compatible (Ollama / LM Studio) ────────────────────────────────────
try:
    from openai import AsyncOpenAI
except ImportError:
    AsyncOpenAI = None

from spaf.utils.logger import logger


# ---------------------------------------------------------------------------
# Module-specific prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_BASE = (
    "You are an elite offensive security researcher and Red Team Lead operating "
    "the SPAF framework. Be concise, deeply technical, and professional. "
    "Use GitHub-flavored markdown with code blocks where appropriate."
)

_PROMPTS: Dict[str, str] = {
    "recon": """
You are analyzing PASSIVE RECONNAISSANCE findings from the SPAF framework.

### Findings:
{findings_json}

### Provide a structured Recon Intelligence Report with:
1. **Attack Surface Summary** — key exposure points discovered.
2. **Email / Identity Risks** — phishing / social-engineering angles from WHOIS/DNS leaks.
3. **DNS Misconfiguration Analysis** — SPF, DMARC, zone-transfer risk explanation.
4. **Subdomain Takeover Candidates** — flag any subdomains pointing to unclaimed services.
5. **Recommended Next Steps** — what modules to run next (webscan, network, crawl).

Be specific. Reference actual values from the findings data.
""",

    "network": """
You are analyzing NETWORK SCAN findings from the SPAF framework.

### Findings:
{findings_json}

### Provide a structured Network Threat Intelligence Report with:
1. **Exposed Service Summary** — table of open ports, services, and risk level.
2. **Critical Attack Vectors** — for each high/critical port: describe the specific exploit path.
3. **CVE Exploitation Paths** — for any CVEs listed, provide CVSS score context and PoC approach.
4. **Lateral Movement Potential** — how an attacker could pivot from these services.
5. **Firewall / Segmentation Recommendations** — specific rules to close each gap.

Reference actual port numbers, products, and versions from the findings.
""",

    "webscan": """
You are analyzing WEB SECURITY SCAN findings from the SPAF framework.

### Findings:
{findings_json}

### Provide a structured Web Penetration Assessment Report with:
1. **Critical Finding Highlights** — top-3 most dangerous issues and why.
2. **Header Misconfiguration Exploitation** — how missing headers enable XSS, clickjacking, MIME sniffing.
3. **TLS/Certificate Risk** — practical impact of any TLS weaknesses found.
4. **Sensitive Path Exposure** — describe what an attacker can do with each exposed path.
5. **WAF Bypass Suggestions** — techniques relevant to these specific misconfigurations.
6. **Developer Remediation Code** — provide actual HTTP response header configs (nginx/apache/node).

Reference exact header names, paths, and status codes from the findings.
""",

    "crawler": """
You are analyzing WEB CRAWLER findings from the SPAF framework.

### Findings:
{findings_json}

### Provide a structured Web Application Recon Report with:
1. **Attack Surface Map** — key pages, forms, and endpoints discovered.
2. **Form Vulnerability Analysis** — for each form found: CSRF risk, injection points, auth bypass potential.
3. **Sensitive Keyword Analysis** — what leaked keywords suggest about backend tech/secrets.
4. **High-Value Targets** — which crawled endpoints are most likely vulnerable to SQLi, XSS, IDOR.
5. **Recommended Active Scan Payloads** — specific payloads to test against the discovered attack surface.

Reference actual URLs and finding types from the data.
""",
}


class AIOrchestrator:
    def __init__(self):
        self.provider        = os.getenv("AI_PROVIDER", "google").lower()
        self.google_key      = os.getenv("GOOGLE_API_KEY")
        self.anthropic_key   = os.getenv("ANTHROPIC_API_KEY")
        self.ollama_url      = os.getenv("OLLAMA_URL", "http://localhost:11434/v1")
        self.lm_studio_url   = os.getenv("LM_STUDIO_URL", "http://localhost:1234/v1")
        self.google_model    = os.getenv("GOOGLE_MODEL", "gemini-2.0-flash")
        self.anthropic_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")

        # ── Google GenAI (new SDK) ────────────────────────────────────────
        self._google_client = None
        if self.google_key and google_genai:
            self._google_client = google_genai.Client(api_key=self.google_key)

        # ── Anthropic ────────────────────────────────────────────────────
        self.anthropic_client = (
            anthropic.AsyncAnthropic(api_key=self.anthropic_key)
            if (self.anthropic_key and anthropic)
            else None
        )

        # ── Local models (Ollama / LM Studio) ────────────────────────────
        self.local_client = None
        if self.provider == "ollama" and AsyncOpenAI:
            self.local_client = AsyncOpenAI(base_url=self.ollama_url, api_key="ollama")
        elif self.provider == "lmstudio" and AsyncOpenAI:
            self.local_client = AsyncOpenAI(base_url=self.lm_studio_url, api_key="lmstudio")

    # ------------------------------------------------------------------
    # Core dispatch
    # ------------------------------------------------------------------

    async def _call(self, system_msg: str, user_prompt: str, max_tokens: int = 4096) -> str:
        try:
            # ── Google GenAI (new SDK) ────────────────────────────────────
            if self.provider == "google" and self._google_client:
                full_prompt = f"{system_msg}\n\n{user_prompt}"
                response = await self._google_client.aio.models.generate_content(
                    model=self.google_model,
                    contents=full_prompt,
                )
                return response.text

            # ── Anthropic Claude ──────────────────────────────────────────
            elif self.provider == "claude" and self.anthropic_client:
                response = await self.anthropic_client.messages.create(
                    model=self.anthropic_model,
                    max_tokens=max_tokens,
                    system=system_msg,
                    messages=[{"role": "user", "content": user_prompt}],
                )
                return response.content[0].text

            # ── Local (Ollama / LM Studio) ────────────────────────────────
            elif self.local_client:
                model_name = os.getenv("LOCAL_MODEL")
                if not model_name:
                    try:
                        models = await self.local_client.models.list()
                        if models.data:
                            model_name = models.data[0].id
                    except Exception:
                        model_name = "local-model"

                response = await self.local_client.chat.completions.create(
                    model=model_name or "local-model",
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user",   "content": user_prompt},
                    ],
                )
                return response.choices[0].message.content

            return (
                "⚠️  AI provider not configured. "
                "Set AI_PROVIDER and the corresponding API key in your .env file."
            )

        except Exception as e:
            logger.error(f"AI call failed [{self.provider}]: {e}")
            return f"Error: {str(e)}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def chat(self, prompt: str) -> str:
        """General-purpose AI interaction (`spaf chat`, `spaf shell`, watch alerts)."""
        return await self._call(_SYSTEM_BASE, prompt)

    async def analyze_findings(self, findings: list) -> str:
        """Full Red Team assessment report from a raw findings list (`spaf analyze`)."""
        prompt = f"""
Analyze these security findings and provide a professional Red Team Assessment Report.

### Findings Data:
{json.dumps(findings, indent=2, default=str)}

### Report Structure:
1. **Executive Summary** — high-level impact assessment.
2. **Technical Deep Dive** — for each finding: explain the vulnerability, root cause, and specific risk.
   - **Exploitation Path**: describe a potential attack chain.
3. **Advanced Bypass Strategies** — how to bypass WAF, EDR, IPS related to these findings.
4. **CVE Correlation** — map findings to specific high-impact CVEs if applicable.
5. **Prioritized Remediation** — practical step-by-step fix instructions.

Use GitHub-flavored markdown with code blocks for payloads and remediation scripts.
"""
        return await self._call(_SYSTEM_BASE, prompt, max_tokens=4096)

    async def analyze_module(self, module_name: str, findings: List[Dict[str, Any]]) -> str:
        """
        Module-specific AI analysis — called automatically after every scan.
        module_name: recon | network | webscan | crawler
        Falls back to generic analysis if module_name is unknown.
        """
        if not findings:
            return "No findings to analyze."

        template = _PROMPTS.get(module_name)
        if not template:
            return await self.analyze_findings(findings)

        findings_json = json.dumps(findings, indent=2, default=str)
        prompt = template.format(findings_json=findings_json)
        return await self._call(_SYSTEM_BASE, prompt, max_tokens=4096)

    async def generate_poc(self, finding: Dict[str, Any]) -> str:
        """Generate a Python PoC exploit script for a single finding."""
        prompt = f"""
Generate a Python Proof-of-Concept (POC) script for the following vulnerability.

Vulnerability Details:
{json.dumps(finding, indent=2, default=str)}

Requirements:
1. Standalone Python file using 'requests' or 'aiohttp'.
2. Include browser-like headers.
3. Comment every section of the exploit.
4. Print clear success/failure messages.
5. ONLY output the code wrapped in markdown code blocks.
"""
        return await self._call(_SYSTEM_BASE, prompt)

    async def generate_remediation(self, finding: Dict[str, Any], fmt: str = "ansible") -> str:
        """Generate automated remediation code in the requested format."""
        prompt = f"""
Generate functional {fmt} code to remediate/fix the following security finding.

Finding:
{json.dumps(finding, indent=2, default=str)}

Requirements:
1. Production-ready code following best practices.
2. Comments explaining what each section does.
3. Address the specific vulnerability mentioned.
4. ONLY output the code wrapped in markdown code blocks.
"""
        return await self._call(_SYSTEM_BASE, prompt)


ai_orchestrator = AIOrchestrator()
