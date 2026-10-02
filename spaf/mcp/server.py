"""
SPAF MCP server.

Exposes SPAF's modules and the autonomous agent as MCP tools so any MCP host
(Claude Desktop, IDEs, other agents) can drive SPAF locally. Safety model:

* Scope is enforced inside every active tool — out-of-scope targets are refused
  and there is **no bypass flag** exposed to the model.
* `agent_run` defaults to plan-only; active execution needs an explicit
  `dry_run=False` and an in-scope target.
* There is no raw-command tool — the model only selects SPAF's fixed modules.
* Every active call is written to the audit log.

stdio transport only in this release (what Claude Desktop launches). Networked
HTTP transport comes later, behind the secure gateway with authentication.
"""

import functools
import logging
import sys
from typing import Any, Dict

# mcp 2.x renamed FastMCP -> MCPServer; fall back to 1.x for older installs.
try:
    from mcp.server.mcpserver import MCPServer as _MCP
except ImportError:  # pragma: no cover - depends on installed mcp version
    from mcp.server.fastmcp import FastMCP as _MCP

from spaf.service import SpafService, ScopeError
from spaf.mcp import shaping

INSTRUCTIONS = (
    "SPAF — AI-orchestrated offensive security. Drive recon, the external recon "
    "toolkit, network/web scans, and an autonomous agent. AUTHORIZED TESTING "
    "ONLY. Set the engagement scope first with scope_add; active tools refuse "
    "out-of-scope targets. agent_run is plan-only unless dry_run is set to false."
)


def _route_logs_to_stderr() -> None:
    """stdout carries the MCP protocol — send all logging to stderr instead."""
    root = logging.getLogger()
    for lg in (root, logging.getLogger("SPAF")):
        for h in list(lg.handlers):
            lg.removeHandler(h)
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def build_server(scope_file: str = "scope.json"):
    _route_logs_to_stderr()
    svc = SpafService(scope_file=scope_file)
    try:
        from spaf.cli.main import get_version
        version = get_version()
    except Exception:
        version = "0"

    mcp = _MCP(name="spaf", instructions=INSTRUCTIONS, version=version)

    def _scope_guard(fn):
        """Turn a ScopeError into a structured, actionable result.

        functools.wraps preserves the wrapped signature so the MCP SDK still
        generates the correct input schema from the real parameters.
        """
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except ScopeError as exc:
                return {"error": "out_of_scope", "message": str(exc),
                        "hint": "Call scope_add with an authorized target first."}
        return wrapper

    # ── Scope & status (read / safe) ──────────────────────────────────
    @mcp.tool()
    def scope_show() -> Dict[str, Any]:
        """Show the current engagement scope (in-scope and out-of-scope entries)."""
        return svc.scope_state().model_dump()

    @mcp.tool()
    def scope_add(value: str) -> Dict[str, Any]:
        """Add a domain, IP, or CIDR to the in-scope list. Authorized targets only."""
        return svc.scope_add(value).model_dump()

    @mcp.tool()
    def tools_status() -> Dict[str, Any]:
        """List which external recon binaries (subfinder, httpx, nuclei, …) are installed."""
        return {"tools": [t.model_dump() for t in svc.tools_status()]}

    # ── Active modules (scope-gated) ──────────────────────────────────
    @mcp.tool()
    @_scope_guard
    async def recon(target: str, passive: bool = True) -> Dict[str, Any]:
        """Map a target's attack surface: subdomains, DNS records, WHOIS, optional active checks."""
        r = await svc.run_module("recon", target, {"passive": passive}, surface="mcp")
        return shaping.scan_payload(r)

    @mcp.tool()
    @_scope_guard
    async def toolkit(target: str, nuclei_severity: str = "critical,high,medium") -> Dict[str, Any]:
        """Run the external recon pipeline (subfinder → httpx → katana → nuclei, …) on a target."""
        r = await svc.run_module("toolkit", target, {"nuclei_severity": nuclei_severity}, surface="mcp")
        return shaping.scan_payload(r)

    @mcp.tool()
    @_scope_guard
    async def scan(target: str, ports: str = "1-1024", intensity: str = "normal") -> Dict[str, Any]:
        """Network port scan (nmap) with service/version detection and CVE mapping."""
        r = await svc.run_module("scan", target, {"ports": ports, "intensity": intensity}, surface="mcp")
        return shaping.scan_payload(r)

    @mcp.tool()
    @_scope_guard
    async def webscan(url: str) -> Dict[str, Any]:
        """Web security audit: security headers, cookie flags, TLS, and sensitive paths."""
        r = await svc.run_module("webscan", url, {}, surface="mcp")
        return shaping.scan_payload(r)

    @mcp.tool()
    @_scope_guard
    async def crawl(url: str, depth: int = 2) -> Dict[str, Any]:
        """Spider a web application to discover endpoints and forms."""
        r = await svc.run_module("crawl", url, {"depth": depth}, surface="mcp")
        return shaping.scan_payload(r)

    @mcp.tool()
    @_scope_guard
    async def agent_run(target: str, goal: str = "", dry_run: bool = True,
                        aggressive: bool = False) -> Dict[str, Any]:
        """Autonomous agent. dry_run=True (default) returns only the plan; set
        dry_run=False to actually run the chained assessment (in-scope targets only)."""
        r = await svc.run_agent(target, goal, dry_run=dry_run, aggressive=aggressive, surface="mcp")
        return shaping.agent_payload(r)

    # ── Resources (read-only context) ─────────────────────────────────
    @mcp.resource("spaf://scope")
    def scope_resource() -> str:
        import json
        return json.dumps(svc.scope_state().model_dump(), indent=2)

    @mcp.resource("spaf://tools")
    def tools_resource() -> str:
        import json
        return json.dumps([t.model_dump() for t in svc.tools_status()], indent=2)

    # ── Prompt ────────────────────────────────────────────────────────
    @mcp.prompt()
    def assess_target(target: str) -> str:
        """Prompt template: plan and summarize an assessment of a target."""
        return (f"Plan an authorized security assessment of {target} using SPAF's "
                f"tools (scope_add first if needed), then run them and summarize the "
                f"highest-risk findings with concrete remediation.")

    return mcp


def run(scope_file: str = "scope.json") -> None:
    """Entry point for `spaf mcp` — serve over stdio."""
    build_server(scope_file).run("stdio")
