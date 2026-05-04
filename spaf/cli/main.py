import asyncio
import os
import json
import importlib.util
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table

from spaf.core.engine import ScanEngine
from spaf.database.mongo import db
from spaf.utils.validator import validate_target, validate_url, sanitize_domain
from spaf.utils.logger import logger

# Modules
from spaf.modules.recon import ReconModule
from spaf.modules.network import NetworkModule
from spaf.modules.webscan import WebscanModule
from spaf.modules.crawler import CrawlerModule
from spaf.reports.generator import ReportGenerator
from spaf.utils.ai import ai_orchestrator
from spaf.utils.auth import auth_manager
from rich.panel import Panel

app = typer.Typer(
    help="Smart Pentesting Automation Framework (SPAF) - AI-Augmented Offensive Security Framework. Developed by gg",
    rich_markup_mode="rich"
)
console = Console()
engine = ScanEngine()

def load_targets(target_arg: str) -> List[str]:
    """Loads targets from a file or returns a list with a single target."""
    if os.path.isfile(target_arg):
        with open(target_arg, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return [target_arg]

def print_banner():
    status = "[bold green]ONLINE[/bold green]" if auth_manager.is_logged_in() else "[bold yellow]OFFLINE[/bold yellow]"
    banner = f"""[bold green]
  ██████  ██████   █████  ███████ 
  ██       ██   ██ ██   ██ ██      
  ██████  ██████  ███████ █████   
       ██ ██      ██   ██ ██      
  ██████  ██      ██   ██ ██      
  [/bold green]
  [dim white]Smart Pentesting Automation Framework[/dim white] | Status: {status}
  [bold blue]Developed by gg[/bold blue]
    """
    console.print(banner)

def load_plugins(app_instance: typer.Typer):
    """Dynamically loads plugins from the 'plugins' directory."""
    plugins_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "plugins")
    if not os.path.exists(plugins_dir):
        os.makedirs(plugins_dir, exist_ok=True)
        return
        
    for filename in os.listdir(plugins_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            plugin_path = os.path.join(plugins_dir, filename)
            spec = importlib.util.spec_from_file_location(filename[:-3], plugin_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(module)
                    if hasattr(module, "register"):
                        module.register(app_instance)
                        logger.info(f"Loaded plugin: {filename}")
                except Exception as e:
                    logger.error(f"Failed to load plugin {filename}: {e}")

async def _init_db():
    await db.connect()

@app.command()
def chat(
    query: str = typer.Argument(..., help="Question or prompt for the configured AI"),
):
    """Directly chat with the configured AI provider (Google, Claude, Ollama, etc.)."""
    async def run():
        with console.status(f"[bold cyan]{ai_orchestrator.provider.capitalize()} is thinking..."):
            response = await ai_orchestrator.chat(query)
            console.print(Panel(response, title=f"{ai_orchestrator.provider.capitalize()} AI", border_style="blue"))
            
    asyncio.run(run())

@app.command()
def gemini(
    query: str = typer.Argument(..., help="Question or prompt for Gemini AI"),
):
    """Shortcut to chat specifically with Google Gemini AI."""
    async def run():
        # Temporarily switch to google provider if not already
        old_provider = ai_orchestrator.provider
        ai_orchestrator.provider = "google"
        try:
            with console.status("[bold cyan]Gemini is thinking..."):
                response = await ai_orchestrator.chat(query)
                console.print(Panel(response, title="Gemini AI", border_style="blue"))
        finally:
            ai_orchestrator.provider = old_provider
            
    asyncio.run(run())

@app.command()
def poc(
    finding_id: str = typer.Argument(..., help="The ID of the finding to generate a POC for"),
    output: Optional[str] = typer.Option(None, "--output", help="Save the POC to a file")
):
    """Generate a functional Proof-of-Concept (POC) script for a specific finding."""
    async def run():
        await _init_db()
        finding = await db.get_finding(finding_id)
        if not finding:
            console.print("[bold red]Error:[/bold red] Finding not found in database.")
            return

        with console.status("[bold cyan]AI is crafting a functional POC script..."):
            prompt = f"""
            Generate a Python Proof-of-Concept (POC) script for the following vulnerability.
            
            Vulnerability Details:
            {json.dumps(finding, indent=2)}
            
            Requirements:
            1. The script must be a standalone Python file using 'requests' or 'aiohttp'.
            2. Include headers to mimic a real browser.
            3. Add comments explaining each part of the exploit.
            4. Print clear success/failure messages.
            5. ONLY output the code, wrapped in markdown code blocks.
            """
            poc_code = await ai_orchestrator.chat(prompt)
            
            # Extract code from markdown blocks
            import re
            code_match = re.search(r"```(?:python)?\n(.*?)\n```", poc_code, re.DOTALL)
            clean_code = code_match.group(1) if code_match else poc_code
            
            console.print(Panel(clean_code, title=f"POC Script: {finding['vuln_type']}", border_style="yellow"))
            
            if output:
                with open(output, "w") as f:
                    f.write(clean_code)
                console.print(f"[bold green]Saved POC to:[/bold green] {output}")
            
    asyncio.run(run())

@app.command()
def watch(
    target: str = typer.Argument(..., help="Target to monitor"),
    interval: int = typer.Option(3600, "--interval", help="Scan interval in seconds (default: 1 hour)"),
    module: str = typer.Option("recon", "--module", help="Module to run (recon, webscan, network, crawl)")
):
    """Monitor a target continuously and alert on changes."""
    async def run():
        try:
            await _init_db()
        except ConnectionError:
            console.print("[bold red]Database Error:[/bold red] Could not connect to MongoDB. Use --no-db flag if available.")
            raise typer.Exit(1)

        console.print(f"[bold cyan]Shadow Scan started for {target}[/bold cyan] (Interval: {interval}s)")
        module_map = {
            "recon": ReconModule,
            "webscan": WebscanModule,
            "network": NetworkModule,
            "crawl": CrawlerModule
        }
        mod_class = module_map.get(module)
        if not mod_class:
            console.print(f"[bold red]Error:[/bold red] Unknown module {module}")
            return

        last_findings_count = -1
        while True:
            console.print(f"[dim]{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} - Running scheduled scan...[/dim]")
            results = await engine.run_module(mod_class, target, {"no_db": False})
            
            current_count = len(results)
            if last_findings_count != -1 and current_count > last_findings_count:
                new_count = current_count - last_findings_count
                console.print(Panel(f"[bold red]ALERT![/bold red] {new_count} new findings detected for {target}!", border_style="red"))
                new_findings = results[last_findings_count:]
                summary = await ai_orchestrator.chat(f"Summarize these NEW findings briefly: {json.dumps(new_findings)}")
                console.print(f"[bold yellow]AI Summary:[/bold yellow] {summary}")
                
            last_findings_count = current_count
            await asyncio.sleep(interval)

    asyncio.run(run())

@app.command()
def shell():
    """Enter the SPAF Interactive Shell for real-time security assistance."""
    console.print("[bold green]Welcome to the SPAF Interactive Shell![/bold green]")
    console.print("Type 'exit' to quit. Use 'chat <query>' or 'analyze <id>' for assistance.")
    
    async def run_shell():
        while True:
            try:
                command = console.input("[bold cyan]SPAF > [/bold cyan]").strip()
                if not command: continue
                if command.lower() in ["exit", "quit"]: break
                
                parts = command.split(" ", 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""
                
                if cmd in ["chat", "gemini"]:
                    with console.status(f"[bold cyan]{ai_orchestrator.provider.capitalize()} is thinking..."):
                        response = await ai_orchestrator.chat(arg)
                        console.print(Panel(response, title="AI Response", border_style="blue"))
                elif cmd == "analyze":
                    await _init_db()
                    findings = await db.get_vulnerabilities_for_scan(arg)
                    with console.status("[bold cyan]AI Analyst is working..."):
                        analysis = await ai_orchestrator.analyze_findings(findings)
                        console.print(Panel(analysis, title="Scan Analysis", border_style="magenta"))
                elif cmd == "help":
                    console.print("[bold white]Available commands:[/bold white]")
                    console.print("  chat <query>    - Talk to the configured AI")
                    console.print("  analyze <id>   - Analyze a specific scan")
                    console.print("  exit           - Exit the shell")
                else:
                    console.print(f"[yellow]Unknown shell command: {cmd}. Type 'help' for options.[/yellow]")
            except KeyboardInterrupt:
                break
            except Exception as e:
                console.print(f"[bold red]Error:[/bold red] {e}")

    asyncio.run(run_shell())

@app.command()
def remediate(
    finding_id: str = typer.Argument(..., help="The ID of the finding to generate remediation code for"),
    format: str = typer.Option("ansible", "--format", help="Remediation format (ansible, terraform, bash, cloud-config)")
):
    """Generate automated remediation code (Ansible, Terraform, etc.) to fix a finding."""
    async def run():
        await _init_db()
        finding = await db.get_finding(finding_id)
        if not finding:
            console.print("[bold red]Error:[/bold red] Finding not found.")
            return

        with console.status(f"[bold cyan]AI is generating {format} remediation code..."):
            prompt = f"""
            Generate functional {format} code to remediate/fix the following security finding.
            
            Finding: {json.dumps(finding, indent=2)}
            
            Requirements:
            1. The code must be production-ready and follow best practices.
            2. Include comments explaining what the code does.
            3. Ensure it addresses the specific vulnerability mentioned.
            4. ONLY output the code, wrapped in markdown code blocks.
            """
            remediation_code = await ai_orchestrator.chat(prompt)
            console.print(Panel(remediation_code, title=f"Remediation: {finding['vuln_type']} ({format})", border_style="green"))
            
    asyncio.run(run())

@app.command()
def setup():
    """Interactive setup to create or update the .env configuration file."""
    console.print("[bold blue]SPAF Configuration Setup[/bold blue]")
    
    config = {}
    config["AI_PROVIDER"] = typer.prompt("Select AI Provider (google, claude, ollama, lmstudio)", default="google")
    
    if config["AI_PROVIDER"] == "google":
        config["GOOGLE_API_KEY"] = typer.prompt("Enter Google API Key", hide_input=True)
    elif config["AI_PROVIDER"] == "claude":
        config["ANTHROPIC_API_KEY"] = typer.prompt("Enter Anthropic API Key", hide_input=True)
    
    config["SPAF_MONGO_URI"] = typer.prompt("Enter MongoDB URI", default="mongodb://localhost:27017")
    config["USE_TOR"] = typer.confirm("Enable TOR routing by default?", default=False)
    
    env_content = "\n".join([f"{k}={v}" for k, v in config.items()])
    
    with open(".env", "w") as f:
        f.write("# SPAF Configuration\n")
        f.write(env_content)
        f.write("\nRANDOM_USER_AGENT=true\nSPAF_LOG_LEVEL=INFO\n")
        
    console.print("[bold green]Configuration saved to .env[/bold green]")

@app.command()
def test_ai():
    """Verify connectivity and responsiveness of the configured AI provider."""
    async def run():
        console.print(f"[bold cyan]Testing connection to {ai_orchestrator.provider.capitalize()}...[/bold cyan]")
        test_prompt = "Say 'SPAF AI is Online' if you can read this."
        try:
            with console.status("[bold yellow]Waiting for AI response..."):
                response = await ai_orchestrator.chat(test_prompt)
                if "SPAF AI is Online" in response or len(response) > 0:
                    console.print("[bold green]Success![/bold green] AI is responding correctly.")
                    console.print(f"[dim]Response: {response}[/dim]")
                else:
                    console.print("[bold red]Failed![/bold red] AI responded but the output was unexpected.")
        except Exception as e:
            console.print(f"[bold red]Connection Error:[/bold red] {e}")
            
    asyncio.run(run())

@app.command()
def login(
    username: str = typer.Option(..., prompt=True, help="Antigravity Cloud Username"),
    token: str = typer.Option(..., prompt=True, hide_input=True, help="API Token")
):
    """Login to Antigravity Cloud to sync results and use AI features."""
    auth_manager.login(username, token)

@app.command()
def analyze(
    file: Optional[str] = typer.Option(None, "--file", help="JSON result file to analyze"),
    scan_id: Optional[str] = typer.Option(None, "--id", help="Scan ID from database to analyze")
):
    """Use AI to analyze scan results and provide deep insights."""
    async def run():
        findings = []
        if file:
            with open(file, "r") as f:
                findings = json.load(f)
        elif scan_id:
            await _init_db()
            findings = await db.get_vulnerabilities_for_scan(scan_id)
        else:
            console.print("[bold red]Error:[/bold red] Provide either --file or --id")
            return

        with console.status("[bold cyan]AI is analyzing your findings..."):
            analysis = await ai_orchestrator.analyze_findings(findings)
            console.print(Panel(analysis, title="AI Security Insight", border_style="magenta"))
            
    asyncio.run(run())

@app.command()
def recon(
    target: str      = typer.Argument(..., help="Target domain or IP"),
    passive: bool    = typer.Option(True,  "--passive/--active", help="Enable passive reconnaissance"),
    output: Optional[str] = typer.Option(None, "--output", help="Output file for results (JSON)"),
    no_db: bool      = typer.Option(False, "--no-db",  help="Run in offline mode without database logging"),
    no_ai: bool      = typer.Option(False, "--no-ai",  help="Skip automatic AI analysis after scan"),
    delay: float     = typer.Option(0.0,   "--delay",  help="Delay between requests in seconds"),
    concurrency: int = typer.Option(5,     "--concurrency", help="Maximum concurrent requests")
):
    """Perform reconnaissance on one or more targets."""
    targets = load_targets(target)

    async def run():
        if not no_db:
            try:
                await _init_db()
            except ConnectionError:
                console.print("[bold red]Database Error:[/bold red] Could not connect to MongoDB. Use --no-db for offline mode.")
                raise typer.Exit(1)

        options = {
            "passive":     passive,
            "no_db":       no_db,
            "no_ai":       no_ai,
            "delay":       delay,
            "concurrency": concurrency,
        }

        tasks = [engine.run_module(ReconModule, t, options) for t in targets]
        all_results = await asyncio.gather(*tasks)

        if output:
            flat_results = [item for sublist in all_results for item in sublist]
            with open(output, "w") as f:
                json.dump(flat_results, f, indent=4)
            console.print(f"[green]All results saved to:[/green] {output}")

    asyncio.run(run())

@app.command()
def scan(
    target: str      = typer.Argument(..., help="Target domain or IP"),
    ports: str       = typer.Option("1-1024", "--ports",      help="Port range (e.g., 1-65535)"),
    intensity: str   = typer.Option("normal", "--intensity",  help="Scan intensity: light|normal|aggressive"),
    scanner: str     = typer.Option("nmap",   "--scanner",    help="Scanner engine: nmap|rustscan"),
    ulimit: int      = typer.Option(5000,      "--ulimit",     help="RustScan: open file descriptor limit"),
    batch_size: int  = typer.Option(2500,      "--batch-size", help="RustScan: ports per batch"),
    no_db: bool      = typer.Option(False,     "--no-db",      help="Run in offline mode without database logging"),
    no_ai: bool      = typer.Option(False,     "--no-ai",      help="Skip automatic AI analysis after scan"),
):
    """Run a network port scan using Nmap or RustScan on one or more targets."""
    targets = load_targets(target)

    if intensity not in ["light", "normal", "aggressive"]:
        console.print("[bold red]Error:[/bold red] Intensity must be light, normal, or aggressive.")
        raise typer.Exit(1)

    if scanner not in ["nmap", "rustscan"]:
        console.print("[bold red]Error:[/bold red] Scanner must be nmap or rustscan.")
        raise typer.Exit(1)

    async def run():
        if not no_db:
            try:
                await _init_db()
            except ConnectionError:
                raise typer.Exit(1)

        options = {
            "ports":      ports,
            "intensity":  intensity,
            "scanner":    scanner,
            "ulimit":     ulimit,
            "batch_size": batch_size,
            "no_db":      no_db,
            "no_ai":      no_ai,
        }
        tasks = [engine.run_module(NetworkModule, t, options) for t in targets]
        await asyncio.gather(*tasks)

    asyncio.run(run())


@app.command()
def webscan(
    url: str              = typer.Argument(..., help="Target URL (including protocol)"),
    headers_only: bool    = typer.Option(False, "--headers-only",  help="Only check security headers"),
    output: Optional[str] = typer.Option(None,  "--output",        help="Output file for results (JSON)"),
    no_db: bool           = typer.Option(False, "--no-db",         help="Run in offline mode without database logging"),
    no_ai: bool           = typer.Option(False, "--no-ai",         help="Skip automatic AI analysis after scan"),
    delay: float          = typer.Option(0.0,   "--delay",         help="Delay between requests in seconds"),
    concurrency: int      = typer.Option(5,     "--concurrency",   help="Maximum concurrent requests")
):
    """Perform a web security assessment on one or more targets."""
    targets = load_targets(url)

    async def run():
        if not no_db:
            try:
                await _init_db()
            except ConnectionError:
                raise typer.Exit(1)

        options = {
            "headers_only": headers_only,
            "no_db":        no_db,
            "no_ai":        no_ai,
            "delay":        delay,
            "concurrency":  concurrency,
        }
        tasks = [engine.run_module(WebscanModule, t, options) for t in targets]
        all_results = await asyncio.gather(*tasks)

        if output:
            flat_results = [item for sublist in all_results for item in sublist]
            with open(output, "w") as f:
                json.dump(flat_results, f, indent=4)
            console.print(f"[green]All results saved to:[/green] {output}")

    asyncio.run(run())

@app.command()
def crawl(
    url: str              = typer.Argument(..., help="Target URL (including protocol)"),
    depth: int            = typer.Option(2,     "--depth",     help="Maximum crawl depth"),
    max_pages: int        = typer.Option(50,    "--max-pages", help="Maximum pages to crawl"),
    output: Optional[str] = typer.Option(None,  "--output",    help="Output file for results (JSON)"),
    no_db: bool           = typer.Option(False, "--no-db",     help="Run in offline mode"),
    no_ai: bool           = typer.Option(False, "--no-ai",     help="Skip automatic AI analysis after scan"),
):
    """Spider a web application and identify interesting endpoints."""
    targets = load_targets(url)

    async def run():
        if not no_db:
            try:
                await _init_db()
            except ConnectionError:
                raise typer.Exit(1)

        options = {
            "depth":     depth,
            "max_pages": max_pages,
            "no_db":     no_db,
            "no_ai":     no_ai,
        }
        tasks = [engine.run_module(CrawlerModule, t, options) for t in targets]
        all_results = await asyncio.gather(*tasks)

        if output:
            flat_results = [item for sublist in all_results for item in sublist]
            with open(output, "w") as f:
                json.dump(flat_results, f, indent=4)
            console.print(f"[green]All results saved to:[/green] {output}")

    asyncio.run(run())

@app.command()
def report(
    target: Optional[str] = typer.Argument(None, help="Target to generate report for"),
    format: str = typer.Option("both", "--format", help="Report format: html|json|both"),
    output_dir: str = typer.Option("./reports", "--output-dir", help="Directory to save reports"),
    from_file: Optional[str] = typer.Option(None, "--from-file", help="Generate report from a local JSON results file")
):
    """Generate a security report for a target from database history or local file."""
    if not target and not from_file:
        console.print("[bold red]Error:[/bold red] You must provide either a target or a results file using --from-file.")
        raise typer.Exit(1)

    if target:
        target = sanitize_domain(target)
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    async def run():
        findings = []
        report_target = target

        if from_file:
            try:
                with open(from_file, "r") as f:
                    findings = json.load(f)
                if not report_target:
                    # Try to infer target from findings
                    if findings and isinstance(findings, list) and 'target' in findings[0]:
                        report_target = findings[0]['target']
                    else:
                        report_target = "imported_scan"
                console.print(f"[cyan]Loaded {len(findings)} findings from file: {from_file}[/cyan]")
            except Exception as e:
                console.print(f"[bold red]Error loading file:[/bold red] {e}")
                return
        else:
            await _init_db()
            findings = await db.get_all_vulnerabilities_for_target(report_target)
            
        if not findings:
            console.print(f"[yellow]No findings found for target: {report_target}[/yellow]")
            return
            
        meta = {"target": report_target, "total_findings": len(findings)}
        generator = ReportGenerator(report_target, findings, meta)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format in ["json", "both"]:
            json_path = os.path.join(output_dir, f"spaf_report_{report_target}_{timestamp}.json")
            generator.generate_json(json_path)
            console.print(f"[green]JSON report generated:[/green] {json_path}")
            
        if format in ["html", "both"]:
            html_path = os.path.join(output_dir, f"spaf_report_{report_target}_{timestamp}.html")
            generator.generate_html(html_path)
            console.print(f"[green]HTML report generated:[/green] {html_path}")

    asyncio.run(run())

@app.command()
def history(
    target: Optional[str] = typer.Argument(None, help="Target domain or IP (optional)"),
    limit: int = typer.Option(20, "--limit", help="Number of entries to show")
):
    """View scan history."""
    print_banner()
    
    async def run():
        await _init_db()
        scans = await db.get_scan_history(target, limit)
        
        if not scans:
            console.print("[yellow]No scan history found.[/yellow]")
            return

        table = Table(title="SPAF Scan History")
        table.add_column("Date", style="dim")
        table.add_column("Target", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Status", style="bold")
        table.add_column("Findings", style="green")

        for s in scans:
            status_color = "green" if s['status'] == "completed" else "red" if s['status'] == "failed" else "yellow"
            table.add_row(
                s['started_at'].strftime("%Y-%m-%d %H:%M"),
                s['target'],
                s['type'].upper(),
                f"[{status_color}]{s['status']}[/{status_color}]",
                str(s.get('findings_count', 0))
            )
        
        console.print(table)

    asyncio.run(run())

def entry_point():
    load_plugins(app)
    app()

if __name__ == "__main__":
    entry_point()
