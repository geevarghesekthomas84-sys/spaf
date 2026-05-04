import os
import json
import asyncio
from typing import List, Optional, Dict, Any

# ── Google GenAI (new SDK) ────────────────────────────────────────────────────
try:
    from google import genai as google_genai
except ImportError:
    google_genai = None

# ── Anthropic ─────────────────────────────────────────────────────────────────
try:
    import anthropic
except ImportError:
    anthropic = None

# ── OpenAI-compatible (Ollama / LM Studio) ────────────────────────────────────
try:
    from openai import AsyncOpenAI, APIConnectionError as OAIConnectionError
except ImportError:
    AsyncOpenAI       = None
    OAIConnectionError = Exception

from spaf.utils.logger import logger


# ---------------------------------------------------------------------------
# Provider name normalisation
# Accepts: ollama | lmstudio | lm-studio | lm_studio | claude | google
# ---------------------------------------------------------------------------

def _normalise_provider(raw: str) -> str:
    raw = raw.strip().lower().replace("-", "").replace("_", "")
    if raw in ("lmstudio", "lmstudio"):
        return "lmstudio"
    if raw == "claude":
        return "claude"
    if raw == "google":
        return "google"
    if raw == "ollama":
        return "ollama"
    return raw  # pass through unknown values


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
2. **Form Vulnerability Analysis** — for each form found: CSRF risk, injection points, auth bypass.
3. **Sensitive Keyword Analysis** — what leaked keywords suggest about backend tech/secrets.
4. **High-Value Targets** — which crawled endpoints are most likely vulnerable to SQLi, XSS, IDOR.
5. **Recommended Active Scan Payloads** — specific payloads to test against the discovered attack surface.

Reference actual URLs and finding types from the data.
""",
}


class AIOrchestrator:
    def __init__(self):
        raw_provider         = os.getenv("AI_PROVIDER", "google")
        self.provider        = _normalise_provider(raw_provider)
        self.google_key      = os.getenv("GOOGLE_API_KEY")
        self.anthropic_key   = os.getenv("ANTHROPIC_API_KEY")
        self.ollama_url      = os.getenv("OLLAMA_URL",      "http://localhost:11434/v1")
        self.lm_studio_url   = os.getenv("LM_STUDIO_URL",   "http://localhost:1234/v1")
        self.google_model    = os.getenv("GOOGLE_MODEL",    "gemini-2.0-flash")
        self.anthropic_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        # Provider-specific model overrides (fallback to shared LOCAL_MODEL)
        self.ollama_model    = os.getenv("OLLAMA_MODEL")    or os.getenv("LOCAL_MODEL")
        self.lmstudio_model  = os.getenv("LM_STUDIO_MODEL") or os.getenv("LOCAL_MODEL")

        # ── Google GenAI ──────────────────────────────────────────────────
        self._google_client = None
        if self.google_key and google_genai:
            self._google_client = google_genai.Client(api_key=self.google_key)

        # ── Anthropic ─────────────────────────────────────────────────────
        self.anthropic_client = (
            anthropic.AsyncAnthropic(api_key=self.anthropic_key)
            if (self.anthropic_key and anthropic)
            else None
        )

        # ── Local: Ollama ─────────────────────────────────────────────────
        self._ollama_client = None
        if AsyncOpenAI and self.provider == "ollama":
            self._ollama_client = AsyncOpenAI(
                base_url=self.ollama_url,
                api_key="ollama",          # Ollama ignores the key but the field is required
            )

        # ── Local: LM Studio ──────────────────────────────────────────────
        self._lmstudio_client = None
        if AsyncOpenAI and self.provider == "lmstudio":
            self._lmstudio_client = AsyncOpenAI(
                base_url=self.lm_studio_url,
                api_key="lm-studio",       # LM Studio ignores the key
            )

    # ------------------------------------------------------------------
    # Model resolution helpers
    # ------------------------------------------------------------------

    async def _resolve_ollama_model(self) -> str:
        """
        Return the model to use for Ollama.
        Priority: OLLAMA_MODEL env > first model from /v1/models > 'llama3'
        """
        if self.ollama_model:
            return self.ollama_model
        try:
            response = await asyncio.wait_for(
                self._ollama_client.models.list(), timeout=5
            )
            if response.data:
                model = response.data[0].id
                logger.debug(f"Ollama: auto-selected model '{model}'")
                return model
        except asyncio.TimeoutError:
            logger.warning("Ollama: model list timed out — using 'llama3' as fallback")
        except Exception as exc:
            logger.warning(f"Ollama: could not list models ({exc}) — using 'llama3' as fallback")
        return "llama3"

    async def _resolve_lmstudio_model(self) -> str:
        """
        Return the model to use for LM Studio.
        LM Studio loads one model at a time; we just need the model identifier.
        Priority: LM_STUDIO_MODEL env > first model from /v1/models > 'local-model'
        """
        if self.lmstudio_model:
            return self.lmstudio_model
        try:
            response = await asyncio.wait_for(
                self._lmstudio_client.models.list(), timeout=5
            )
            if response.data:
                model = response.data[0].id
                logger.debug(f"LM Studio: auto-selected model '{model}'")
                return model
        except asyncio.TimeoutError:
            logger.warning("LM Studio: model list timed out — using 'local-model' as fallback")
        except Exception as exc:
            logger.warning(
                f"LM Studio: could not list models ({exc}) — using 'local-model' as fallback. "
                "Make sure LM Studio is running with Server mode enabled."
            )
        return "local-model"

    # ------------------------------------------------------------------
    # Health check — used by `spaf test-ai`
    # ------------------------------------------------------------------

    async def health_check(self) -> Dict[str, Any]:
        """
        Verify the configured AI provider is reachable and functional.
        Returns a dict: {provider, status, model, detail}
        """
        result: Dict[str, Any] = {
            "provider": self.provider,
            "status":   "❌ FAIL",
            "model":    "—",
            "detail":   "",
        }

        try:
            if self.provider == "google":
                if not self._google_client:
                    result["detail"] = "GOOGLE_API_KEY is not set."
                    return result
                resp = await asyncio.wait_for(
                    self._google_client.aio.models.generate_content(
                        model=self.google_model,
                        contents="Reply with OK",
                    ),
                    timeout=15,
                )
                result.update(status="✅ OK", model=self.google_model, detail=resp.text.strip()[:60])

            elif self.provider == "claude":
                if not self.anthropic_client:
                    result["detail"] = "ANTHROPIC_API_KEY is not set."
                    return result
                resp = await asyncio.wait_for(
                    self.anthropic_client.messages.create(
                        model=self.anthropic_model,
                        max_tokens=16,
                        messages=[{"role": "user", "content": "Reply with OK"}],
                    ),
                    timeout=15,
                )
                result.update(status="✅ OK", model=self.anthropic_model,
                               detail=resp.content[0].text.strip()[:60])

            elif self.provider == "ollama":
                if not self._ollama_client:
                    result["detail"] = "openai package not installed. Run: pip install openai"
                    return result
                model = await self._resolve_ollama_model()
                resp  = await asyncio.wait_for(
                    self._ollama_client.chat.completions.create(
                        model=model,
                        max_tokens=16,
                        messages=[
                            {"role": "system", "content": "You are a helpful assistant."},
                            {"role": "user",   "content": "Reply with OK"},
                        ],
                    ),
                    timeout=30,
                )
                result.update(status="✅ OK", model=model,
                               detail=resp.choices[0].message.content.strip()[:60])

            elif self.provider == "lmstudio":
                if not self._lmstudio_client:
                    result["detail"] = "openai package not installed. Run: pip install openai"
                    return result
                model = await self._resolve_lmstudio_model()
                resp  = await asyncio.wait_for(
                    self._lmstudio_client.chat.completions.create(
                        model=model,
                        max_tokens=16,
                        messages=[
                            {"role": "system", "content": "You are a helpful assistant."},
                            {"role": "user",   "content": "Reply with OK"},
                        ],
                    ),
                    timeout=30,
                )
                result.update(status="✅ OK", model=model,
                               detail=resp.choices[0].message.content.strip()[:60])

            else:
                result["detail"] = f"Unknown provider: '{self.provider}'"

        except asyncio.TimeoutError:
            result["detail"] = "Request timed out. Check that the service is running."
        except OAIConnectionError:
            base = self.ollama_url if self.provider == "ollama" else self.lm_studio_url
            result["detail"] = (
                f"Connection refused at {base}. "
                f"Make sure {'Ollama' if self.provider == 'ollama' else 'LM Studio'} is running."
            )
        except Exception as exc:
            result["detail"] = str(exc)

        return result

    # ------------------------------------------------------------------
    # Core dispatch
    # ------------------------------------------------------------------

    async def _call(self, system_msg: str, user_prompt: str, max_tokens: int = 4096) -> str:
        try:
            # ── Google ────────────────────────────────────────────────────
            if self.provider == "google":
                if not self._google_client:
                    return "⚠️  GOOGLE_API_KEY not set. Add it to your .env file."
                full_prompt = f"{system_msg}\n\n{user_prompt}"
                response = await self._google_client.aio.models.generate_content(
                    model=self.google_model,
                    contents=full_prompt,
                )
                return response.text

            # ── Anthropic Claude ──────────────────────────────────────────
            elif self.provider == "claude":
                if not self.anthropic_client:
                    return "⚠️  ANTHROPIC_API_KEY not set. Add it to your .env file."
                response = await self.anthropic_client.messages.create(
                    model=self.anthropic_model,
                    max_tokens=max_tokens,
                    system=system_msg,
                    messages=[{"role": "user", "content": user_prompt}],
                )
                return response.content[0].text

            # ── Ollama ────────────────────────────────────────────────────
            elif self.provider == "ollama":
                if not self._ollama_client:
                    return (
                        "⚠️  openai package not installed.\n"
                        "Run: pip install openai\n"
                        "Then set AI_PROVIDER=ollama and OLLAMA_URL in .env"
                    )
                model    = await self._resolve_ollama_model()
                response = await self._ollama_client.chat.completions.create(
                    model=model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user",   "content": user_prompt},
                    ],
                )
                return response.choices[0].message.content

            # ── LM Studio ─────────────────────────────────────────────────
            elif self.provider == "lmstudio":
                if not self._lmstudio_client:
                    return (
                        "⚠️  openai package not installed.\n"
                        "Run: pip install openai\n"
                        "Then set AI_PROVIDER=lmstudio and LM_STUDIO_URL in .env"
                    )
                model    = await self._resolve_lmstudio_model()
                response = await self._lmstudio_client.chat.completions.create(
                    model=model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user",   "content": user_prompt},
                    ],
                )
                return response.choices[0].message.content

            return (
                f"⚠️  Unknown AI provider: '{self.provider}'.\n"
                "Set AI_PROVIDER to: google | claude | ollama | lmstudio"
            )

        except OAIConnectionError:
            base = self.ollama_url if self.provider == "ollama" else self.lm_studio_url
            msg = (
                f"⚠️  Cannot connect to {self.provider} at {base}.\n"
                f"Make sure {'Ollama is running (ollama serve)' if self.provider == 'ollama' else 'LM Studio is running with Server mode enabled'}."
            )
            logger.error(msg)
            return msg

        except asyncio.TimeoutError:
            msg = f"⚠️  {self.provider} request timed out. The model may be loading — try again in a moment."
            logger.error(msg)
            return msg

        except Exception as exc:
            logger.error(f"AI call failed [{self.provider}]: {exc}")
            return f"Error [{self.provider}]: {exc}"

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
