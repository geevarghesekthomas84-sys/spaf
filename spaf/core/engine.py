import os
import aiohttp
from typing import Any, Dict, Type, List
from datetime import datetime
from rich.console import Console
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from spaf.utils.logger import logger
from spaf.database import db
from spaf.utils.proxy import proxy_manager

console = Console()


class ScanEngine:
    def __init__(self):
        self.console = console

    def _print_banner(self):
        # Restraint: per-scan we show only the one-line lockup, not the wordmark.
        from spaf.utils import ui
        try:
            from spaf.cli.main import get_version
            version = get_version()
        except Exception:
            version = "dev"
        self.console.print(ui.lockup(version, False))

    async def run_module(self, module_class: Type, target: str, options: Dict[str, Any]):
        """
        Executes a pentesting module with UI, database logging, and automatic
        AI-powered post-scan analysis.

        Options:
            no_db  (bool) — skip MongoDB logging
            no_ai  (bool) — skip AI analysis after scan completes
        """
        self._print_banner()

        module_name = module_class.__name__.replace("Module", "").lower()
        start_time  = datetime.utcnow()

        # ── Scan Initialization Panel ─────────────────────────────────────
        from spaf.utils import ui
        self.console.print(ui.kv(
            [("target", target),
             ("module", module_name.upper()),
             ("started", start_time.strftime("%Y-%m-%d %H:%M:%S UTC"))],
            title="Scan",
        ))

        # ── Mock mode: run the pipeline without touching any target ────────
        if options.get("mock") or os.getenv("SPAF_MOCK", "").strip().lower() in ("1", "true", "yes", "on"):
            self.console.print(f"[{ui.AMBER}]● MOCK MODE[/] [dim]— no target contacted; synthetic results.[/dim]")
            return [{
                "target": target, "vuln_type": f"mock_{module_name}_finding",
                "detail": f"[MOCK] synthetic {module_name} finding for {target}; no target was touched.",
                "severity": "Info", "severity_order": 5,
                "recommendation": "Mock mode — unset SPAF_MOCK / remove --mock to run for real.",
                "scan_type": module_name, "discovered_at": start_time.isoformat(),
            }]

        # ── Database ──────────────────────────────────────────────────────
        no_db   = options.get("no_db", False)
        scan_id = None
        if not no_db:
            scan_id = await db.create_scan(target, module_name, options)

        module_instance = module_class(target, options, scan_id)

        # ── Progress Bar ──────────────────────────────────────────────────
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )

        results = []
        try:
            with Live(progress, console=self.console, refresh_per_second=10):
                results = await module_instance.run(progress)

            # Persist findings
            findings_count = len(results)
            if not no_db and scan_id:
                for finding in results:
                    await db.upsert_vulnerability(scan_id, finding)
                await db.complete_scan(scan_id, findings_count)

            # Render raw results table
            module_instance.render_results(results)

        except Exception as e:
            logger.exception(f"Error during scan: {e}")
            if not no_db and scan_id:
                await db.fail_scan(scan_id, str(e))
            self.console.print(f"[bold red]Scan failed: {e}[/bold red]")
            return []

        # ── Final Summary Panel ───────────────────────────────────────────
        end_time = datetime.utcnow()
        duration = end_time - start_time

        from spaf.utils import ui
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for r in results:
            sev = r.get("severity", "Info")
            if sev in sev_counts:
                sev_counts[sev] += 1

        sev_parts = [
            f"[{ui.SEVERITY[s]}]{s} {c}[/]"
            for s, c in sev_counts.items() if c > 0
        ]
        sev_str = "  ".join(sev_parts) if sev_parts else f"[{ui.FAINT}]none[/]"

        self.console.print(ui.kv(
            [("findings", sev_str),
             ("elapsed", str(duration).split(".")[0]),
             ("status", f"[{ui.OK}]completed[/]")],
            title="Summary", tone=ui.OK,
        ))

        # ── AI Post-Scan Analysis ─────────────────────────────────────────
        no_ai = options.get("no_ai", False)
        if not no_ai and results:
            await self._run_ai_analysis(module_name, target, results)

        return results

    async def _run_ai_analysis(self, module_name: str, target: str, results: List[Dict[str, Any]]):
        """
        Calls the AI orchestrator with a module-specific prompt and renders
        the analysis in a highlighted panel.
        """
        # Lazy import to avoid circular dependency at module load time
        from spaf.utils.ai import ai_orchestrator
        from spaf.utils import ui

        self.console.print()
        self.console.print(ui.eyebrow("AI Threat Intelligence"))
        self.console.print(
            f"[{ui.FAINT}]Analyzing {len(results)} finding(s) via "
            f"{ai_orchestrator.provider.upper()}…[/]\n"
        )

        with self.console.status(
            f"[{ui.AMBER}]Thinking…[/]", spinner="dots"
        ):
            analysis = await ai_orchestrator.analyze_module(module_name, results)

        self.console.print(ui.panel(
            analysis,
            title=f"Analysis · {module_name.upper()} · {target}",
        ))
        self.console.print()


class BaseModule:
    """Base class for all SPAF modules."""

    def __init__(self, target: str, options: Dict[str, Any], scan_id: str = None):
        self.target  = target
        self.options = options
        self.scan_id = scan_id
        self.console = console

    def get_session(self) -> aiohttp.ClientSession:
        """Returns a proxy-aware aiohttp session."""
        headers = {"User-Agent": proxy_manager.get_user_agent()}
        return aiohttp.ClientSession(
            headers=headers,
            connector=aiohttp.TCPConnector(ssl=False),
        )

    def get_request_params(self) -> Dict[str, Any]:
        """Returns parameters for a request, including the current proxy."""
        params = {}
        proxy  = proxy_manager.get_proxy()
        if proxy:
            params["proxy"] = proxy
        return params

    async def run(self, progress: Progress) -> List[Dict[str, Any]]:
        raise NotImplementedError("Modules must implement run()")

    def render_results(self, results: List[Dict[str, Any]]):
        raise NotImplementedError("Modules must implement render_results()")
