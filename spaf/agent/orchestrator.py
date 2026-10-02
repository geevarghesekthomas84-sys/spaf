"""
SPAF Autonomous Agent
=====================

An AI-driven orchestrator that chains SPAF's modules into an end-to-end
assessment. Given a target (and optional goal), the configured AI plans an
ordered sequence of steps from a fixed, safe toolset; the agent executes each
step through the normal scan engine (so DB logging and rendering still work),
accumulates findings, and finishes with a single consolidated AI assessment.

Design principles:
* **Fixed action set.** The AI only chooses *which* of SPAF's existing modules
  to run and in what order — it never executes arbitrary commands.
* **Scope-safe.** Active steps are gated by the engagement scope, exactly like
  `spaf toolkit`.
* **Degrades without AI.** With `--no-ai` (or if planning fails) it falls back to
  a sensible default playbook.
"""

import json
import re
from typing import Any, Dict, List, Optional

from spaf.modules.recon import ReconModule
from spaf.modules.network import NetworkModule
from spaf.modules.webscan import WebscanModule
from spaf.modules.crawler import CrawlerModule
from spaf.modules.toolkit import ToolkitModule
from spaf.utils.logger import logger
from spaf.utils.scope import is_in_scope
from spaf.utils.validator import validate_url

# The only modules the agent may run, by name.
ACTIONS: Dict[str, Any] = {
    "recon":   ReconModule,
    "toolkit": ToolkitModule,
    "scan":    NetworkModule,
    "webscan": WebscanModule,
    "crawl":   CrawlerModule,
}

# Steps that actively touch the target (scope-gated).
ACTIVE_ACTIONS = {"toolkit", "scan", "webscan", "crawl"}

# Fallback plan when AI planning is unavailable or fails.
DEFAULT_PLAYBOOK = ["recon", "toolkit", "webscan", "scan"]

_AGENT_SYSTEM = (
    "You are the autonomous brain of SPAF, an authorized offensive-security "
    "framework. Be precise, technical, and safety-aware. Authorized testing only."
)

_ASSESS_PROMPT = """You are writing the final assessment for a SPAF engagement.

### Findings (JSON):
{findings}

Produce a concise Red Team assessment: the top risks with impact, the most
likely exploitation path, and prioritized, concrete remediation. Use markdown.
"""

_PLAN_PROMPT = """You are the planning brain of SPAF, an authorized penetration-testing framework.
Plan an assessment of the target below by choosing an ordered sequence of steps
from this FIXED set of modules (you may not invent others):

- recon    : passive + active recon (subdomains, DNS, WHOIS)
- toolkit  : external recon pipeline (subfinder, httpx, katana, nuclei, ...)
- webscan  : web security audit (headers, TLS, sensitive paths)
- crawl    : spider the web app for endpoints
- scan     : network port scan (nmap) + CVE mapping

Target: {target}
Goal: {goal}

Respond with ONLY a JSON array of steps, most useful first, e.g.:
[{{"module": "recon", "reason": "map the attack surface"}},
 {{"module": "webscan", "reason": "check web security posture"}}]
Include a module at most once. No prose, just the JSON array."""


class PentestAgent:
    def __init__(self, target: str, goal: str, options: Dict[str, Any], console):
        self.target = target
        self.goal = goal or "Perform a general security assessment and surface the highest-risk findings."
        self.options = options
        self.console = console
        self.scope = options.get("scope")
        self.findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Planning
    # ------------------------------------------------------------------
    async def plan(self) -> List[Dict[str, str]]:
        if self.options.get("no_ai"):
            return self._default_plan("AI planning disabled (--no-ai)")

        from spaf.orchestration import default_orchestrator
        prompt = _PLAN_PROMPT.format(target=self.target, goal=self.goal)
        try:
            raw = await default_orchestrator().complete(
                "plan", _AGENT_SYSTEM, prompt, budget=self.options.get("budget"))
            steps = self._parse_plan(raw)
            if steps:
                return steps
            logger.warning("Agent: could not parse an AI plan; using the default playbook.")
        except Exception as exc:
            logger.warning(f"Agent: AI planning failed ({exc}); using the default playbook.")
        return self._default_plan("fell back from AI planning")

    def _parse_plan(self, raw: str) -> List[Dict[str, str]]:
        """Extract a JSON array of {module, reason} steps from an AI response."""
        match = re.search(r"\[.*\]", raw or "", re.DOTALL)
        if not match:
            return []
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return []

        steps: List[Dict[str, str]] = []
        seen = set()
        for item in data:
            if not isinstance(item, dict):
                continue
            module = str(item.get("module", "")).strip().lower()
            if module in ACTIONS and module not in seen:
                seen.add(module)
                steps.append({"module": module, "reason": str(item.get("reason", "")).strip()})
        return steps

    def _default_plan(self, note: str) -> List[Dict[str, str]]:
        self.console.print(f"[dim]Using default playbook ({note}).[/dim]")
        plan = []
        for module in DEFAULT_PLAYBOOK:
            # Skip network scan for explicit URL targets; keep it for hosts/domains.
            if module == "scan" and validate_url(self.target):
                continue
            plan.append({"module": module, "reason": "default playbook"})
        return plan

    # ------------------------------------------------------------------
    # Scope
    # ------------------------------------------------------------------
    def scope_blocks(self, module: str) -> bool:
        if module not in ACTIVE_ACTIONS or not self.scope:
            return False
        return not is_in_scope(self.target, self.scope)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def _module_options(self, module: str) -> Dict[str, Any]:
        no_db = self.options.get("no_db", False)
        aggressive = self.options.get("aggressive", False)
        base = {"no_db": no_db, "no_ai": True}  # final AI pass summarizes everything
        if module == "recon":
            base.update({"passive": not aggressive})
        elif module == "toolkit":
            base.update({
                "subs": True, "probe": True, "crawl": True, "urls": True,
                "nuclei": True, "fuzz": False, "depth": 2,
                "nuclei_severity": "critical,high,medium" if not aggressive else "critical,high,medium,low",
                "nuclei_dast": aggressive, "scope": self.scope,
            })
        elif module == "scan":
            base.update({
                "scanner": "nmap", "ports": "1-1024",
                "intensity": "aggressive" if aggressive else "normal",
            })
        elif module == "crawl":
            base.update({"depth": 2, "max_pages": 50})
        return base

    async def execute(self, engine, steps: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        from rich.rule import Rule
        for i, step in enumerate(steps, 1):
            module = step["module"]
            if self.scope_blocks(module):
                self.console.print(
                    f"[yellow]Step {i}/{len(steps)} · {module}: skipped — target is out of engagement scope.[/yellow]"
                )
                continue
            self.console.print()
            self.console.print(Rule(
                f"[bold magenta]Agent step {i}/{len(steps)} · {module.upper()}[/bold magenta]"
                + (f" — [dim]{step['reason']}[/dim]" if step.get("reason") else ""),
                style="magenta",
            ))
            try:
                results = await engine.run_module(ACTIONS[module], self.target, self._module_options(module))
                if results:
                    self.findings.extend(results)
            except Exception as exc:
                logger.error(f"Agent step '{module}' failed: {exc}")
                self.console.print(f"[red]Step '{module}' failed: {exc}[/red]")
        return self.findings

    # ------------------------------------------------------------------
    # Final assessment
    # ------------------------------------------------------------------
    async def summarize(self) -> Optional[str]:
        if self.options.get("no_ai") or not self.findings:
            return None
        from spaf.orchestration import default_orchestrator
        prompt = _ASSESS_PROMPT.format(
            findings=json.dumps([f for f in self.findings], indent=2, default=str)[:60000]
        )
        try:
            out = await default_orchestrator().complete(
                "analyze", _AGENT_SYSTEM, prompt, budget=self.options.get("budget"))
            return None if out.lstrip().startswith(("⚠️", "Error [")) else out
        except Exception as exc:
            logger.warning(f"Agent: final AI assessment failed ({exc}).")
            return None
