import asyncio
import aiohttp
from typing import Any, Dict, Type, List
from datetime import datetime
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from spaf.utils.logger import logger
from spaf.database.mongo import db
from spaf.utils.proxy import proxy_manager

console = Console()

class ScanEngine:
    def __init__(self):
        self.console = console

    def _print_banner(self):
        banner = """
 [bold green]
  ██████  ██████   █████  ███████ 
 ██       ██   ██ ██   ██ ██      
  ██████  ██████  ███████ █████   
       ██ ██      ██   ██ ██      
  ██████  ██      ██   ██ ██      
 [/bold green]
 [dim white]Smart Pentesting Automation Framework[/dim white]
 [bold blue]Developed by gg[/bold blue]
        """
        self.console.print(banner)

    async def run_module(self, module_class: Type, target: str, options: Dict[str, Any]):
        """
        Executes a specific pentesting module with UI updates and database logging.
        """
        self._print_banner()
        
        module_name = module_class.__name__.replace("Module", "").lower()
        start_time = datetime.utcnow()
        
        # Initial Summary Panel
        summary_table = Table.grid(padding=(0, 2))
        summary_table.add_row("[cyan]Target:[/cyan]", target)
        summary_table.add_row("[cyan]Module:[/cyan]", module_name.upper())
        summary_table.add_row("[cyan]Start Time (UTC):[/cyan]", start_time.strftime("%Y-%m-%d %H:%M:%S"))
        
        self.console.print(Panel(summary_table, title="[bold white]Scan Initialization[/bold white]", border_style="blue"))

        # Database initialization (skip if offline)
        no_db = options.get("no_db", False)
        scan_id = None
        if not no_db:
            scan_id = await db.create_scan(target, module_name, options)
        
        module_instance = module_class(target, options, scan_id)
        
        # Progress Bar setup
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True
        )
        
        results = []
        try:
            with Live(progress, console=self.console, refresh_per_second=10):
                results = await module_instance.run(progress)
            
            # Record results to DB (skip if offline)
            findings_count = len(results)
            if not no_db and scan_id:
                for finding in results:
                    await db.upsert_vulnerability(scan_id, finding)
                await db.complete_scan(scan_id, findings_count)
            
            # Module specific results rendering
            module_instance.render_results(results)
            
        except Exception as e:
            logger.exception(f"Error during scan: {e}")
            if not no_db and scan_id:
                await db.fail_scan(scan_id, str(e))
            self.console.print(f"[bold red]Scan failed: {e}[/bold red]")
            return

        end_time = datetime.utcnow()
        duration = end_time - start_time
        
        # Final Summary Panel
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for r in results:
            sev = r.get("severity", "Info")
            if sev in sev_counts:
                sev_counts[sev] += 1
        
        sev_summary = []
        colors = {"Critical": "bold red", "High": "orange3", "Medium": "yellow", "Low": "cyan", "Info": "dim white"}
        for sev, count in sev_counts.items():
            if count > 0:
                sev_summary.append(f"[{colors[sev]}]{sev}: {count}[/{colors[sev]}]")
        
        sev_str = " | ".join(sev_summary) if sev_summary else "[dim]None[/dim]"

        final_table = Table.grid(padding=(0, 2))
        final_table.add_row("[cyan]Findings:[/cyan]", sev_str)
        final_table.add_row("[cyan]Elapsed Time:[/cyan]", str(duration).split('.')[0])
        final_table.add_row("[cyan]Status:[/cyan]", "[bold green]COMPLETED[/bold green]")
        
        self.console.print(Panel(final_table, title="[bold white]Scan Summary[/bold white]", border_style="green"))
        return results

class BaseModule:
    """
    Base class for all SPAF modules.
    """
    def __init__(self, target: str, options: Dict[str, Any], scan_id: str = None):
        self.target = target
        self.options = options
        self.scan_id = scan_id
        self.console = console

    def get_session(self) -> aiohttp.ClientSession:
        """Returns a proxy-aware aiohttp session."""
        headers = {"User-Agent": proxy_manager.get_user_agent()}
        return aiohttp.ClientSession(
            headers=headers,
            connector=aiohttp.TCPConnector(ssl=False)
        )

    def get_request_params(self) -> Dict[str, Any]:
        """Returns parameters for a request, including the current proxy."""
        params = {}
        proxy = proxy_manager.get_proxy()
        if proxy:
            params["proxy"] = proxy
        return params

    async def run(self, progress: Progress) -> List[Dict[str, Any]]:
        raise NotImplementedError("Modules must implement run()")

    def render_results(self, results: List[Dict[str, Any]]):
        raise NotImplementedError("Modules must implement render_results()")
