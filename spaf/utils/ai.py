import os
import aiohttp
import json
from typing import Optional, Dict, Any
try:
    import google.generativeai as genai
except ImportError:
    genai = None

try:
    import anthropic
except ImportError:
    anthropic = None

try:
    from openai import AsyncOpenAI
except ImportError:
    AsyncOpenAI = None
from spaf.utils.logger import logger

class AIOrchestrator:
    def __init__(self):
        self.provider = os.getenv("AI_PROVIDER", "google").lower()
        self.google_key = os.getenv("GOOGLE_API_KEY")
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/v1")
        self.lm_studio_url = os.getenv("LM_STUDIO_URL", "http://localhost:1234/v1")
        
        # Initialize clients
        if self.google_key and genai:
            genai.configure(api_key=self.google_key)
            
        self.anthropic_client = anthropic.AsyncAnthropic(api_key=self.anthropic_key) if (self.anthropic_key and anthropic) else None
        
        # Local models via OpenAI-compatible API
        self.local_client = None
        if self.provider == "ollama" and AsyncOpenAI:
            self.local_client = AsyncOpenAI(base_url=self.ollama_url, api_key="ollama")
        elif self.provider == "lmstudio" and AsyncOpenAI:
            self.local_client = AsyncOpenAI(base_url=self.lm_studio_url, api_key="lmstudio")

    async def chat(self, prompt: str) -> str:
        """General purpose chat method for direct AI interaction."""
        try:
            system_msg = "You are an elite offensive security expert using the SPAF framework. Be concise, technical, and professional."
            
            if self.provider == "google" and self.google_key:
                model = genai.GenerativeModel('gemini-pro')
                response = await model.generate_content_async(f"{system_msg}\n\nUser: {prompt}")
                return response.text
                
            elif self.provider == "claude" and self.anthropic_client:
                response = await self.anthropic_client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=2048,
                    system=system_msg,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
                
            elif self.local_client:
                model_name = os.getenv("LOCAL_MODEL")
                if not model_name:
                    try:
                        models = await self.local_client.models.list()
                        if models.data: model_name = models.data[0].id
                    except Exception: model_name = "local-model"

                response = await self.local_client.chat.completions.create(
                    model=model_name or "local-model",
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": prompt}
                    ]
                )
                return response.choices[0].message.content
                
            return "AI Provider not configured properly or API keys missing."
        except Exception as e:
            logger.error(f"AI Chat failed: {e}")
            return f"Error: {str(e)}"

    async def analyze_findings(self, findings: list) -> str:
        system_msg = "You are an expert Red Team Lead and Offensive Security Specialist. Analyze findings from the SPAF Framework."
        prompt = f"""
        Analyze these security findings and provide a professional Red Team Assessment Report.
        
        ### Findings Data:
        {json.dumps(findings, indent=2)}
        
        ### Report Structure:
        1. **Executive Summary**: High-level impact assessment.
        2. **Technical Deep Dive**: 
           - For each finding: Explain the vulnerability, its root cause, and the specific risk.
           - **Exploitation Path**: Describe a potential attack chain to escalate this finding.
        3. **Advanced Bypass Strategies**: How to bypass modern security controls (WAF, EDR, IPS) related to these findings.
        4. **CVE Correlation**: Map findings to specific, high-impact CVEs if applicable.
        5. **Prioritized Remediation**: Practical, step-by-step fix instructions for developers.
        
        Use high-quality GitHub-flavored markdown with code blocks for payloads and remediation scripts.
        """
        
        try:
            if self.provider == "google" and self.google_key:
                model = genai.GenerativeModel('gemini-pro')
                response = await model.generate_content_async(f"{system_msg}\n\n{prompt}")
                return response.text
                
            elif self.provider == "claude" and self.anthropic_client:
                response = await self.anthropic_client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=4096,
                    system=system_msg,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
                
            elif self.local_client:
                model_name = os.getenv("LOCAL_MODEL")
                if not model_name:
                    try:
                        models = await self.local_client.models.list()
                        if models.data: model_name = models.data[0].id
                    except Exception: model_name = "local-model"

                response = await self.local_client.chat.completions.create(
                    model=model_name or "local-model",
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": prompt}
                    ]
                )
                return response.choices[0].message.content
                
            else:
                return "AI Provider not configured or unavailable."
                
        except Exception as e:
            logger.error(f"AI Analysis failed: {e}")
            return f"Error during AI analysis: {str(e)}"

ai_orchestrator = AIOrchestrator()
