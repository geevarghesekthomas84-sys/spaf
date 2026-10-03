"""
SpafService — the UI-free facade the API and MCP server call.

It runs modules headlessly (no stdout, so it is safe under the MCP stdio
transport), enforces engagement scope centrally, writes an audit record for
every active action, emits progress on an optional EventBus, and returns typed
models. The CLI keeps its own rich-rendered paths; this is for programmatic use.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.progress import Progress

from spaf.modules.recon import ReconModule
from spaf.modules.network import NetworkModule
from spaf.modules.webscan import WebscanModule
from spaf.modules.crawler import CrawlerModule
from spaf.modules.toolkit import ToolkitModule, TOOL_REGISTRY
from spaf.utils.logger import logger
from spaf.utils import scope as scopelib
from spaf.service import audit
from spaf.service.events import Event, EventBus
from spaf.service.models import (
    AgentPlanStep, AgentResult, Finding, ScanResult, ScanSummary,
    ScopeState, ToolStatus, severity_counts,
)

MODULE_MAP: Dict[str, Any] = {
    "recon": ReconModule,
    "toolkit": ToolkitModule,
    "scan": NetworkModule,
    "webscan": WebscanModule,
    "crawl": CrawlerModule,
}


class ScopeError(PermissionError):
    """Raised when a target is outside the enforced engagement scope."""


class SpafService:
    def __init__(self, scope_file: str = "scope.json", *,
                 audit_path: Optional[str] = None, actor: str = "local",
                 engagement: Optional[str] = None):
        self.scope_file = scope_file
        self.audit_path = audit_path
        self.actor = actor
        self.engagement = engagement
        self._db_ready: Optional[bool] = None

    def _audit(self, action: str, target: str, **kw: Any) -> None:
        kw.setdefault("actor", self.actor)
        audit.record(action, target, engagement=self.engagement,
                     path=self.audit_path, **kw)

    # ------------------------------------------------------------------
    # Scope
    # ------------------------------------------------------------------
    def scope_state(self) -> ScopeState:
        data = scopelib.load_scope(self.scope_file)
        return ScopeState(
            in_scope=data.get("in_scope", []),
            out_of_scope=data.get("out_of_scope", []),
            enforced=scopelib.has_scope(data),
        )

    def is_allowed(self, target: str) -> bool:
        return scopelib.is_in_scope(target, scopelib.load_scope(self.scope_file))

    def scope_add(self, value: str) -> ScopeState:
        data = scopelib.load_scope(self.scope_file)
        if value not in data["in_scope"]:
            data["in_scope"].append(value)
            scopelib.save_scope(self.scope_file, data)
        self._audit("scope_add", value, scope_ok=True)
        return self.scope_state()

    def _check_scope(self, target: str, surface: str) -> None:
        data = scopelib.load_scope(self.scope_file)
        if scopelib.has_scope(data) and not scopelib.is_in_scope(target, data):
            self._audit("scope_denied", target, scope_ok=False, surface=surface)
            raise ScopeError(
                f"{target} is outside the engagement scope in {self.scope_file}. "
                f"Add it with scope_add (authorized targets only)."
            )

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------
    async def _ensure_db(self, no_db: bool) -> bool:
        if no_db:
            return False
        if self._db_ready is not None:
            return self._db_ready
        from spaf.database import db
        try:
            await db.connect()
            self._db_ready = True
        except Exception as exc:  # degrade gracefully rather than fail the call
            logger.warning(f"service: database unavailable ({exc}); running without persistence.")
            self._db_ready = False
        return self._db_ready

    # ------------------------------------------------------------------
    # Module execution (headless)
    # ------------------------------------------------------------------
    def _resolve_module(self, module: str):
        """Built-in module, else a registered plugin module."""
        module = module.strip().lower()
        if module in MODULE_MAP:
            return MODULE_MAP[module]
        from spaf import plugins
        cls = plugins.get_module(module)
        if cls is None:
            valid = list(MODULE_MAP) + list(plugins.registered_modules())
            raise ValueError(f"unknown module '{module}'. Valid: {', '.join(sorted(set(valid)))}")
        return cls

    async def run_module(self, module: str, target: str,
                         options: Optional[Dict[str, Any]] = None,
                         *, bus: Optional[EventBus] = None,
                         surface: str = "service") -> ScanResult:
        module = module.strip().lower()
        mod_cls = self._resolve_module(module)

        options = dict(options or {})
        self._check_scope(target, surface)
        self._audit(f"run_module:{module}", target, scope_ok=True, surface=surface)

        if bus:
            bus.publish(Event("run_started", target=target, module=module))

        started = datetime.utcnow()
        no_db = options.get("no_db", False)
        db_ready = await self._ensure_db(no_db)
        scan_id = None
        if db_ready:
            from spaf.database import db
            scan_id = await db.create_scan(target, module, options)

        result = ScanResult(scan_id=scan_id, module=module, target=target, started_at=started)
        try:
            instance = mod_cls(target, options, scan_id)
            progress = Progress(disable=True)  # satisfies module.run(progress), renders nothing
            if bus:
                bus.publish(Event("step_started", target=target, module=module))
            raw = await instance.run(progress)
            findings = [Finding.from_dict(f) for f in (raw or [])]
            result.findings = findings
            result.counts = severity_counts(findings)
            result.completed_at = datetime.utcnow()

            if db_ready and scan_id:
                from spaf.database import db
                for f in (raw or []):
                    await db.upsert_vulnerability(scan_id, f)
                await db.complete_scan(scan_id, len(findings))

            if bus:
                for f in findings:
                    bus.publish(Event("finding", target=target, module=module,
                                      message=f.vuln_type, data={"severity": f.severity}))
                bus.publish(Event("run_completed", target=target, module=module,
                                  data={"count": len(findings)}))
        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            result.completed_at = datetime.utcnow()
            if db_ready and scan_id:
                from spaf.database import db
                await db.fail_scan(scan_id, str(exc))
            if bus:
                bus.publish(Event("run_failed", target=target, module=module, message=str(exc)))
            logger.error(f"service.run_module({module}) failed: {exc}")
        return result

    # ------------------------------------------------------------------
    # Agent
    # ------------------------------------------------------------------
    async def plan_agent(self, target: str, goal: str = "") -> List[AgentPlanStep]:
        from spaf.agent.orchestrator import PentestAgent
        from rich.console import Console
        scope_data = scopelib.load_scope(self.scope_file)
        ag = PentestAgent(target, goal, {"scope": scope_data}, Console(quiet=True))
        steps = await ag.plan()
        return [AgentPlanStep(module=s["module"], reason=s.get("reason", ""),
                              scope_ok=not ag.scope_blocks(s["module"])) for s in steps]

    async def run_agent(self, target: str, goal: str = "", *, dry_run: bool = True,
                        aggressive: bool = False, bus: Optional[EventBus] = None,
                        surface: str = "service") -> AgentResult:
        plan = await self.plan_agent(target, goal)
        result = AgentResult(target=target, goal=goal, dry_run=dry_run, plan=plan)
        if dry_run:
            self._audit("agent_plan", target, scope_ok=self.is_allowed(target), surface=surface)
            return result

        # Active execution: target must be in scope; each step runs headless.
        self._check_scope(target, surface)
        self._audit("agent_run", target, scope_ok=True, surface=surface,
                    extra={"aggressive": aggressive})
        all_findings: List[Finding] = []
        for step in plan:
            if not step.scope_ok:
                continue
            opts: Dict[str, Any] = {"no_db": True}
            if step.module == "recon":
                opts["passive"] = not aggressive
            elif step.module == "scan":
                opts["intensity"] = "aggressive" if aggressive else "normal"
            elif step.module == "toolkit":
                opts.update({"nuclei_dast": aggressive, "scope": scopelib.load_scope(self.scope_file)})
            sr = await self.run_module(step.module, target, opts, bus=bus, surface=surface)
            all_findings.extend(sr.findings)

        result.findings = all_findings
        result.counts = severity_counts(all_findings)
        # Final AI assessment (best-effort).
        if all_findings:
            try:
                from spaf.utils.ai import ai_orchestrator
                result.assessment = await ai_orchestrator.analyze_findings(
                    [f.model_dump() for f in all_findings]
                )
            except Exception as exc:
                logger.warning(f"service: agent assessment failed ({exc}).")
        return result

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    async def list_scans(self, target: Optional[str] = None, limit: int = 20) -> List[ScanSummary]:
        if not await self._ensure_db(False):
            return []
        from spaf.database import db
        rows = await db.get_scan_history(target, limit)
        out = []
        for r in rows:
            out.append(ScanSummary(
                scan_id=str(r.get("_id")), target=r.get("target", ""),
                module=r.get("type", ""), status=r.get("status", ""),
                findings_count=r.get("findings_count", 0),
                started_at=r.get("started_at"),
            ))
        return out

    async def get_findings(self, scan_id: str) -> List[Finding]:
        if not await self._ensure_db(False):
            return []
        from spaf.database import db
        rows = await db.get_vulnerabilities_for_scan(scan_id)
        return [Finding.from_dict(r) for r in rows]

    def tools_status(self) -> List[ToolStatus]:
        import shutil
        return [
            ToolStatus(name=name, installed=shutil.which(name) is not None,
                       role=meta["role"], url=meta["url"])
            for name, meta in TOOL_REGISTRY.items()
        ]
