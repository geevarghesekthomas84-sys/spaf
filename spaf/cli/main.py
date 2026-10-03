import asyncio
import os
import json
import time
import importlib.util
from datetime import datetime
from dotenv import load_dotenv, find_dotenv
# Load .env from the directory the user runs `spaf` in (usecwd=True), not from
# the installed package location. Must run before spaf.database is imported so
# SPAF_DB_BACKEND is honored by the backend selector.
load_dotenv(find_dotenv(usecwd=True))
import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table

from spaf.core.engine import ScanEngine
from spaf.database import db
from spaf.utils.validator import validate_target, sanitize_domain
from spaf.utils.logger import logger

# Modules
from spaf.modules.recon import ReconModule
from spaf.modules.network import NetworkModule
from spaf.modules.webscan import WebscanModule
from spaf.modules.crawler import CrawlerModule
from spaf.modules.toolkit import ToolkitModule, TOOL_REGISTRY
from spaf.reports.generator import ReportGenerator
from spaf.utils.ai import ai_orchestrator
from spaf.utils.auth import auth_manager
from rich.panel import Panel

app = typer.Typer(
    help="Smart Pentesting Automation Framework (SPAF) - AI-Augmented Offensive Security Framework. Developed by gg",
    rich_markup_mode="rich",
    add_completion=True,    # enables: spaf --install-completion / --show-completion
)
console = Console()
engine = ScanEngine()


def get_version() -> str:
    """Return the installed SPAF version (falls back gracefully)."""
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version("spaf")
        except PackageNotFoundError:
            return "dev"
    except Exception:
        return "dev"


__version__ = get_version()


def _version_callback(value: bool):
    if value:
        console.print(f"[bold green]SPAF[/bold green] version [cyan]{get_version()}[/cyan]")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "--version", "-V",
        help="Show the SPAF version and exit.",
        callback=_version_callback, is_eager=True,
    ),
):
    """Smart Pentesting Automation Framework (SPAF)."""
    pass

def load_targets(target_arg: str) -> List[str]:
    """Loads targets from a file or returns a list with a single target."""
    if os.path.isfile(target_arg):
        with open(target_arg, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return [target_arg]

def print_banner(compact: bool = False):
    from spaf.utils import ui
    console.print(ui.banner(get_version(), auth_manager.is_logged_in(), compact=compact))

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


@app.command(name="test-ai")
def test_ai():
    """Test the configured AI provider connection and print a health report."""
    from rich.table import Table

    async def run():
        console.print(f"\n[bold cyan]Testing AI provider:[/bold cyan] [white]{ai_orchestrator.provider.upper()}[/white]\n")
        with console.status("[bold cyan]Connecting to AI provider...[/bold cyan]", spinner="dots"):
            result = await ai_orchestrator.health_check()

        status_color = "green" if "OK" in result["status"] else "red"

        table = Table(title="AI Provider Health Check", show_header=True, header_style="bold white")
        table.add_column("Field",  style="cyan",  width=16)
        table.add_column("Value",  style="white")

        table.add_row("Provider", result["provider"].upper())
        table.add_row("Model",    result["model"])
        table.add_row("Status",   f"[{status_color}]{result['status']}[/{status_color}]")
        table.add_row("Response", result["detail"] or "—")

        console.print(table)

        if "FAIL" in result["status"]:
            console.print(
                "\n[bold yellow]Tip:[/bold yellow] Check your .env file. "
                "Required variables per provider:\n"
                "  google    → GOOGLE_API_KEY\n"
                "  claude    → ANTHROPIC_API_KEY\n"
                "  ollama    → OLLAMA_URL (default: http://localhost:11434/v1)\n"
                "             OLLAMA_MODEL (optional, auto-detected)\n"
                "  lmstudio  → LM_STUDIO_URL (default: http://localhost:1234/v1)\n"
                "             LM_STUDIO_MODEL (optional, auto-detected)\n"
            )

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
def ollama(
    query: str = typer.Argument(..., help="Question or prompt for Ollama (local AI)"),
):
    """Shortcut to chat with a locally running Ollama model (streaming output)."""
    async def run():
        old_provider = ai_orchestrator.provider
        ai_orchestrator.provider = "ollama"
        try:
            model = await ai_orchestrator._resolve_ollama_model()
            console.print(f"\n[bold green]🦙 Ollama — {model}[/bold green]\n")
            await ai_orchestrator.stream_chat(query, console=console)
        finally:
            ai_orchestrator.provider = old_provider

    asyncio.run(run())


@app.command()
def lmstudio(
    query: str = typer.Argument(..., help="Question or prompt for LM Studio (local AI)"),
):
    """Shortcut to chat with the currently loaded LM Studio model (streaming output)."""
    async def run():
        old_provider = ai_orchestrator.provider
        ai_orchestrator.provider = "lmstudio"
        try:
            model = await ai_orchestrator._resolve_lmstudio_model()
            console.print(f"\n[bold yellow]🖥️  LM Studio — {model}[/bold yellow]\n")
            await ai_orchestrator.stream_chat(query, console=console)
        finally:
            ai_orchestrator.provider = old_provider

    asyncio.run(run())


@app.command()
def claude(
    query: str = typer.Argument(..., help="Question or prompt for Anthropic Claude"),
):
    """Shortcut to chat specifically with Anthropic Claude."""
    async def run():
        old_provider = ai_orchestrator.provider
        ai_orchestrator.provider = "claude"
        try:
            with console.status("[bold magenta]Claude is thinking..."):
                response = await ai_orchestrator.chat(query)
            console.print(Panel(response, title="🤖 Anthropic Claude", border_style="magenta"))
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
    target: str   = typer.Argument(..., help="Target to monitor"),
    interval: int = typer.Option(3600,    "--interval", help="Scan interval in seconds (default: 1 hour)"),
    module: str   = typer.Option("recon", "--module",   help="Module to run: recon|webscan|network|crawl|toolkit"),
    no_ai: bool   = typer.Option(False,   "--no-ai",    help="Skip AI analysis after each scheduled scan"),
    no_db: bool   = typer.Option(False,   "--no-db",    help="Run without database logging"),
):
    """Monitor a target continuously and alert on changes (Shadow Scan)."""
    async def run():
        if not no_db:
            try:
                await _init_db()
            except ConnectionError:
                console.print("[bold red]Database Error:[/bold red] Could not connect to MongoDB. Use --no-db flag.")
                raise typer.Exit(1)

        console.print(f"[bold cyan]Shadow Scan started for {target}[/bold cyan] (Interval: {interval}s)")
        module_map = {
            "recon":   ReconModule,
            "webscan": WebscanModule,
            "network": NetworkModule,
            "crawl":   CrawlerModule,
            "toolkit": ToolkitModule,
        }
        mod_class = module_map.get(module)
        if not mod_class:
            console.print(f"[bold red]Error:[/bold red] Unknown module '{module}'")
            return

        options = {"no_db": no_db, "no_ai": no_ai}
        last_findings_count = -1

        while True:
            console.print(f"[dim]{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} - Running scheduled scan...[/dim]")
            results = await engine.run_module(mod_class, target, options)

            current_count = len(results) if results else 0
            if last_findings_count != -1 and current_count > last_findings_count:
                new_count    = current_count - last_findings_count
                new_findings = results[last_findings_count:]
                console.print(
                    Panel(
                        f"[bold red]ALERT![/bold red] {new_count} new finding(s) detected for {target}!",
                        border_style="red",
                    )
                )
                if not no_ai:
                    with console.status("[bold yellow]AI summarizing new findings...[/bold yellow]"):
                        summary = await ai_orchestrator.chat(
                            f"Summarize these NEW security findings briefly in 3 bullet points: "
                            f"{json.dumps(new_findings, default=str)}"
                        )
                    console.print(f"[bold yellow]AI Alert Summary:[/bold yellow]\n{summary}")

            last_findings_count = current_count
            console.print(f"[dim]Next scan in {interval}s. Press Ctrl+C to stop.[/dim]")
            await asyncio.sleep(interval)

    asyncio.run(run())


@app.command(name="ai")
def ai_analyze(
    scan_id: str    = typer.Argument(..., help="Scan ID to re-analyze"),
    module: str     = typer.Option("",  "--module",   help="Module hint: recon|network|webscan|crawler (auto-detected if omitted)"),
    provider: str   = typer.Option("",  "--provider", help="Override AI provider for this call: google|claude|ollama|lmstudio"),
):
    """
    Re-run AI threat analysis on a previous scan without re-scanning.

    Fetches findings from MongoDB by scan ID and sends them through the
    module-specific AI prompt pipeline.
    """
    async def run():
        await _init_db()

        # Fetch findings
        findings = await db.get_vulnerabilities_for_scan(scan_id)
        if not findings:
            console.print(f"[bold red]No findings found for scan ID:[/bold red] {scan_id}")
            raise typer.Exit(1)

        # Auto-detect module from first finding's 'source' field if not given
        mod = module.strip()
        if not mod and findings:
            mod = findings[0].get("source", "").lower()

        # Optional provider override
        if provider:
            import os
            os.environ["AI_PROVIDER"] = provider.lower()
            # Re-instantiate to pick up the override
            from spaf.utils.ai import AIOrchestrator
            orchestrator = AIOrchestrator()
        else:
            orchestrator = ai_orchestrator

        console.print(f"\n[bold magenta]Re-analyzing scan [cyan]{scan_id}[/cyan] "
                      f"([white]{len(findings)}[/white] findings) "
                      f"using [cyan]{mod or 'generic'}[/cyan] prompt via "
                      f"[cyan]{orchestrator.provider.upper()}[/cyan]...[/bold magenta]\n")

        with console.status("[bold magenta]AI is analyzing findings...[/bold magenta]", spinner="dots"):
            analysis = await orchestrator.analyze_module(mod, findings)

        console.print(
            Panel(
                analysis,
                title=f"[bold magenta]🤖 AI Analysis — {scan_id}[/bold magenta]",
                border_style="magenta",
                padding=(1, 2),
            )
        )

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

def _section(title: str, subtitle: str = ""):
    """Print a styled section header for the setup wizard."""
    from spaf.utils import ui
    console.print()
    console.print(ui.eyebrow(title))
    if subtitle:
        console.print(f"[{ui.FAINT}]{subtitle}[/]")


def _provision_mongodb(uri: str) -> bool:
    """
    Best-effort local MongoDB provisioning via Docker.
    Returns True if MongoDB appears reachable afterwards.
    """
    import shutil
    import subprocess
    import socket
    from urllib.parse import urlparse

    def _reachable() -> bool:
        try:
            p = urlparse(uri)
            host = p.hostname or "localhost"
            port = p.port or 27017
            with socket.create_connection((host, port), timeout=2):
                return True
        except Exception:
            return False

    if _reachable():
        console.print("[green]✓ MongoDB is already running and reachable.[/green]")
        return True

    if not shutil.which("docker"):
        console.print(
            "[yellow]Docker not found.[/yellow] Install Docker to auto-provision MongoDB, "
            "or start MongoDB yourself. [dim]Falling back — you can switch to the SQLite "
            "backend for a zero-setup local database.[/dim]"
        )
        return False

    console.print("[cyan]Starting a local MongoDB container (mongo:7) via Docker…[/cyan]")
    # Reuse an existing container if present, else create one.
    subprocess.run(["docker", "start", "spaf-mongo"], capture_output=True, text=True)
    if not _reachable():
        subprocess.run(
            ["docker", "run", "-d", "--name", "spaf-mongo",
             "-p", "27017:27017", "--restart", "unless-stopped", "mongo:7"],
            capture_output=True, text=True,
        )
    # Give it a moment to accept connections.
    for _ in range(10):
        if _reachable():
            console.print("[bold green]✓ Local MongoDB is up on port 27017.[/bold green]")
            return True
        time.sleep(1)
    console.print("[yellow]MongoDB container started but not reachable yet — give it a few seconds.[/yellow]")
    return False


def _provision_sqlite(path: str) -> bool:
    """SQLite needs no server — just make sure the file/dir is writable."""
    import sqlite3
    try:
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        con = sqlite3.connect(path)
        con.close()
        console.print(f"[bold green]✓ SQLite ready at {os.path.abspath(path)} (no server needed).[/bold green]")
        return True
    except Exception as exc:
        console.print(f"[red]Could not initialize SQLite at {path}: {exc}[/red]")
        return False


@app.command()
def setup():
    """Interactive, guided setup — writes your .env and can provision the database locally."""
    from spaf.utils import ui
    from rich.text import Text as _Text

    _body = _Text()
    _body.append("SPAF", style=f"bold {ui.AMBER}")
    _body.append(f"  v{get_version()}\n", style=ui.STEEL)
    _body.append("configuration wizard", style=ui.FAINT)
    console.print(ui.fit_panel(_body))

    config = {}

    # ── AI provider ───────────────────────────────────────────────────
    _section("1 · AI Provider", "Pick the engine that analyzes your findings.")
    provider = typer.prompt(
        "AI provider (google / claude / ollama / lmstudio)", default="google"
    ).strip().lower()
    config["AI_PROVIDER"] = provider

    if provider == "google":
        config["GOOGLE_API_KEY"] = typer.prompt("  Google API key", hide_input=True)
    elif provider == "claude":
        config["ANTHROPIC_API_KEY"] = typer.prompt("  Anthropic API key", hide_input=True)
    elif provider == "ollama":
        config["OLLAMA_URL"] = typer.prompt("  Ollama server URL", default="http://localhost:11434/v1")
        model = typer.prompt("  Ollama model (blank = auto-detect)", default="", show_default=False).strip()
        if model:
            config["OLLAMA_MODEL"] = model
    elif provider in ("lmstudio", "lm-studio", "lm_studio"):
        config["AI_PROVIDER"] = "lmstudio"
        config["LM_STUDIO_URL"] = typer.prompt("  LM Studio server URL", default="http://localhost:1234/v1")
        model = typer.prompt("  LM Studio model (blank = auto-detect)", default="", show_default=False).strip()
        if model:
            config["LM_STUDIO_MODEL"] = model

    # ── Database backend ──────────────────────────────────────────────
    _section("2 · Database", "Where SPAF stores scans & findings. SQLite needs no server.")
    backend = typer.prompt("Database backend [mongodb/sqlite]", default="sqlite").strip().lower()

    if backend in ("sqlite", "sqlite3", "local", "file"):
        config["SPAF_DB_BACKEND"] = "sqlite"
        config["SPAF_SQLITE_PATH"] = typer.prompt("  SQLite file path", default="spaf.db")
        if typer.confirm("  Initialize the SQLite database now?", default=True):
            _provision_sqlite(config["SPAF_SQLITE_PATH"])
    else:
        config["SPAF_DB_BACKEND"] = "mongo"
        config["SPAF_MONGO_URI"] = typer.prompt("  MongoDB URI", default="mongodb://localhost:27017")
        config["SPAF_MONGO_DB"] = typer.prompt("  MongoDB database name", default="spaf")
        if typer.confirm("  Auto-provision a local MongoDB now (via Docker)?", default=False):
            ok = _provision_mongodb(config["SPAF_MONGO_URI"])
            if not ok and typer.confirm(
                "  MongoDB isn't ready. Switch to the zero-setup SQLite backend instead?",
                default=True,
            ):
                config = {k: v for k, v in config.items() if not k.startswith("SPAF_MONGO")}
                config["SPAF_DB_BACKEND"] = "sqlite"
                config["SPAF_SQLITE_PATH"] = "spaf.db"
                _provision_sqlite("spaf.db")

    # ── Stealth ───────────────────────────────────────────────────────
    _section("3 · Stealth & OpsSec")
    config["USE_TOR"] = typer.confirm("Route traffic through TOR by default?", default=False)

    # ── Write .env ────────────────────────────────────────────────────
    env_content = "\n".join([f"{k}={v}" for k, v in config.items()])
    with open(".env", "w") as f:
        f.write("# SPAF Configuration\n")
        f.write(env_content)
        f.write("\nRANDOM_USER_AGENT=true\nSPAF_LOG_LEVEL=INFO\n")

    # ── Summary ───────────────────────────────────────────────────────
    rows = [("AI provider", config.get("AI_PROVIDER", "—"))]
    if config["SPAF_DB_BACKEND"] == "sqlite":
        rows.append(("database", f"SQLite  [{ui.FAINT}]no server[/]"))
        rows.append(("db path", config.get("SPAF_SQLITE_PATH", "spaf.db")))
    else:
        rows.append(("database", "MongoDB"))
        rows.append(("mongo uri", config.get("SPAF_MONGO_URI", "—")))
    rows.append(("tor", "on" if config.get("USE_TOR") else "off"))
    rows.append(("saved to", os.path.abspath(".env")))

    console.print()
    console.print(ui.kv(rows, title="Configuration", tone=ui.OK))
    console.print(
        f"[{ui.OK}]✓ Setup complete.[/]  "
        f"[{ui.FAINT}]Next:[/] [{ui.AMBER}]spaf test-ai[/]"
        f"[{ui.FAINT}]  then  [/][{ui.AMBER}]spaf tools --install[/]"
    )

# NOTE: `test-ai` is defined once above via @app.command(name="test-ai") — the
# detailed health-check with a status table. A second, simpler definition used
# to live here and silently overrode it (both resolved to the CLI name
# "test-ai"); it has been removed.

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

    # Validate every target (defense-in-depth: these are passed to external binaries).
    valid_targets = [t for t in targets if validate_target(sanitize_domain(t))]
    for bad in [t for t in targets if t not in valid_targets]:
        console.print(f"[bold red]Skipping invalid target:[/bold red] {bad}")
    targets = valid_targets
    if not targets:
        console.print("[bold red]Error:[/bold red] No valid targets to scan.")
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
def toolkit(
    target: str           = typer.Argument(..., help="Target domain (or file of targets)"),
    no_subs: bool         = typer.Option(False, "--no-subs",   help="Skip subdomain enumeration (subfinder/assetfinder)"),
    no_probe: bool        = typer.Option(False, "--no-probe",  help="Skip HTTP probing (httpx)"),
    no_crawl: bool        = typer.Option(False, "--no-crawl",  help="Skip active crawling (katana/hakrawler)"),
    no_urls: bool         = typer.Option(False, "--no-urls",   help="Skip historical URL harvesting (waybackurls/gau)"),
    no_nuclei: bool       = typer.Option(False, "--no-nuclei", help="Skip nuclei vulnerability scanning"),
    fuzz: bool            = typer.Option(False, "--fuzz",      help="Enable content fuzzing (ffuf) — requires --wordlist"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", help="Wordlist path for ffuf content fuzzing"),
    depth: int            = typer.Option(2,     "--depth",     help="Crawl depth for katana"),
    nuclei_severity: str  = typer.Option("critical,high,medium", "--nuclei-severity", help="Comma-separated nuclei severities"),
    nuclei_dast: bool     = typer.Option(False, "--nuclei-dast", help="Run nuclei DAST/fuzzing templates against the crawled URL corpus"),
    scope_file: str       = typer.Option("scope.json", "--scope-file", help="Engagement scope file consulted before active scanning"),
    ignore_scope: bool    = typer.Option(False, "--ignore-scope", help="Skip engagement-scope enforcement (dangerous)"),
    output: Optional[str] = typer.Option(None,  "--output",    help="Output file for results (JSON)"),
    no_db: bool           = typer.Option(False, "--no-db",     help="Run in offline mode without database logging"),
    no_ai: bool           = typer.Option(False, "--no-ai",     help="Skip automatic AI analysis after scan"),
):
    """Run the chained external recon pipeline (subfinder → httpx → katana → nuclei, etc.)."""
    from spaf.utils.scope import load_scope, has_scope, is_in_scope

    targets = load_targets(target)

    # ── Engagement-scope enforcement ──────────────────────────────────────
    scope_data = load_scope(scope_file)
    if ignore_scope:
        console.print("[bold red]⚠ Scope enforcement disabled (--ignore-scope).[/bold red]")
        scope_data = None
    elif has_scope(scope_data):
        allowed = [t for t in targets if is_in_scope(t, scope_data)]
        blocked = [t for t in targets if t not in allowed]
        for t in blocked:
            console.print(
                f"[bold red]✗ Skipping out-of-scope target:[/bold red] {t} "
                f"[dim](not in {scope_file}; use 'spaf scope add' or --ignore-scope)[/dim]"
            )
        targets = allowed
        if not targets:
            console.print("[bold red]No in-scope targets to scan.[/bold red]")
            raise typer.Exit(1)
    else:
        console.print(
            f"[yellow]No engagement scope defined in {scope_file}.[/yellow] "
            "[dim]Active scanners will run against every discovered host. "
            "Define one with 'spaf scope add <target>'.[/dim]"
        )

    async def run():
        if not no_db:
            try:
                await _init_db()
            except ConnectionError:
                console.print("[bold red]Database Error:[/bold red] Could not connect to MongoDB. Use --no-db for offline mode.")
                raise typer.Exit(1)

        options = {
            "subs":            not no_subs,
            "probe":           not no_probe,
            "crawl":           not no_crawl,
            "urls":            not no_urls,
            "nuclei":          not no_nuclei,
            "fuzz":            fuzz,
            "wordlist":        wordlist,
            "depth":           depth,
            "nuclei_severity": nuclei_severity,
            "nuclei_dast":     nuclei_dast,
            "scope":           scope_data,
            "no_db":           no_db,
            "no_ai":           no_ai,
        }
        tasks = [engine.run_module(ToolkitModule, t, options) for t in targets]
        all_results = await asyncio.gather(*tasks)

        if output:
            flat_results = [item for sublist in all_results for item in sublist]
            with open(output, "w") as f:
                json.dump(flat_results, f, indent=4)
            console.print(f"[green]All results saved to:[/green] {output}")

    asyncio.run(run())


@app.command()
def tools(
    install: bool = typer.Option(False, "--install", help="Install missing Go-based recon tools via 'go install'"),
    force: bool = typer.Option(False, "--force", help="With --install, (re)install every tool, not just missing ones"),
):
    """List — and optionally install — the external recon binaries SPAF integrates."""
    import shutil

    def render_table():
        from spaf.utils import ui
        table = ui.table("Recon Toolkit")
        table.add_column("Tool", style=ui.AMBER)
        table.add_column("Installed", justify="center")
        table.add_column("Role", style="default")
        table.add_column("Source", style=ui.FAINT)
        miss = []
        for name, meta in TOOL_REGISTRY.items():
            ok = shutil.which(name) is not None
            if not ok:
                miss.append(name)
            status = f"[{ui.OK}]●[/]" if ok else f"[{ui.FAINT}]○[/]"
            table.add_row(name, status, meta["role"], meta["url"])
        console.print(table)
        return miss

    missing = render_table()

    if install:
        _install_tools(missing, force)
        return

    if missing:
        console.print(
            f"\n[yellow]Missing {len(missing)}/{len(TOOL_REGISTRY)} tool(s):[/yellow] "
            f"{', '.join(missing)}"
        )
        console.print(
            "[dim]Install them automatically with [bold]spaf tools --install[/bold] (requires Go), "
            "or grab release binaries from each tool's page above.[/dim]"
        )
    else:
        console.print("\n[bold green]All external recon tools are installed and ready.[/bold green]")


def _install_tools(missing: list, force: bool):
    """Install the Go-based recon tools via 'go install'."""
    import shutil
    import subprocess
    from spaf.modules.toolkit import GO_INSTALL

    if not shutil.which("go"):
        console.print(
            "[bold red]Go toolchain not found.[/bold red] Install Go first: https://go.dev/dl/\n"
            "[dim]Then re-run 'spaf tools --install'. (ffuf and the others are Go programs.)[/dim]"
        )
        raise typer.Exit(1)

    targets = list(GO_INSTALL) if force else missing
    if not targets:
        console.print("[bold green]Nothing to install — all tools are already present.[/bold green]")
        return

    gobin = os.path.expanduser(os.path.join(os.getenv("GOBIN") or "~/go/bin"))
    console.print(f"[cyan]Installing {len(targets)} tool(s) via 'go install' → {gobin}[/cyan]\n")

    ok, failed = [], []
    for name in targets:
        spec = GO_INSTALL.get(name)
        if not spec:
            continue
        with console.status(f"[bold cyan]go install {name}…[/bold cyan]"):
            proc = subprocess.run(
                ["go", "install", spec], capture_output=True, text=True
            )
        if proc.returncode == 0:
            console.print(f"  [green]✓[/green] {name}")
            ok.append(name)
        else:
            console.print(f"  [red]✗[/red] {name}: {proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else 'failed'}")
            failed.append(name)

    console.print(f"\n[bold green]Installed {len(ok)}[/bold green]"
                  + (f", [bold red]{len(failed)} failed[/bold red]" if failed else ""))
    if shutil.which(ok[0]) is None if ok else False:
        console.print(
            f"[yellow]Note:[/yellow] add Go's bin dir to your PATH so SPAF can find the tools:\n"
            f"  [dim]export PATH=\"$PATH:{gobin}\"[/dim]"
        )


@app.command()
def agent(
    target: str           = typer.Argument(..., help="Target domain, IP, or URL"),
    goal: str             = typer.Option("", "--goal", "-g", help="Natural-language objective for the assessment"),
    yes: bool             = typer.Option(False, "--yes", "-y", help="Run the plan without the confirmation prompt"),
    dry_run: bool         = typer.Option(False, "--dry-run", help="Show the plan and exit without running anything"),
    aggressive: bool      = typer.Option(False, "--aggressive", help="Deeper/active settings (aggressive nmap, nuclei DAST, active recon)"),
    scope_file: str       = typer.Option("scope.json", "--scope-file", help="Engagement scope file for active steps"),
    ignore_scope: bool    = typer.Option(False, "--ignore-scope", help="Disable scope enforcement (dangerous)"),
    output: Optional[str] = typer.Option(None, "--output", help="Save all findings to a JSON file"),
    no_db: bool           = typer.Option(False, "--no-db", help="Run without database logging"),
    no_ai: bool           = typer.Option(False, "--no-ai", help="Skip AI planning and the final assessment (uses the default playbook)"),
):
    """Autonomous agent — the AI plans and chains SPAF modules to assess a target end-to-end."""
    from spaf.agent import PentestAgent
    from spaf.agent.orchestrator import ACTIVE_ACTIONS
    from spaf.utils.scope import load_scope, has_scope, is_in_scope
    from spaf.utils import ui

    print_banner()

    # Scope setup (gates active steps).
    scope_data = load_scope(scope_file)
    if ignore_scope:
        console.print("[bold red]⚠ Scope enforcement disabled (--ignore-scope).[/bold red]")
        scope_data = None
    elif has_scope(scope_data) and not is_in_scope(target, scope_data):
        console.print(
            f"[bold red]✗ {target} is out of engagement scope[/bold red] "
            f"[dim]({scope_file}). Add it with 'spaf scope add', or use --ignore-scope.[/dim]"
        )
        raise typer.Exit(1)

    options = {
        "no_db": no_db, "no_ai": no_ai, "aggressive": aggressive, "scope": scope_data,
    }

    async def run():
        if not no_db:
            try:
                await _init_db()
            except ConnectionError:
                console.print(
                    "[bold red]Database Error:[/bold red] Could not connect. "
                    "Use --no-db, or run 'spaf setup' and pick the SQLite backend."
                )
                raise typer.Exit(1)

        ag = PentestAgent(target, goal, options, console)

        # 1) Plan
        with console.status("[bold magenta]Agent is planning the assessment…[/bold magenta]"):
            steps = await ag.plan()

        plan_table = ui.table(f"Assessment Plan · {target}")
        plan_table.add_column("#", style=ui.FAINT, width=3, justify="right")
        plan_table.add_column("Module", style=ui.AMBER)
        plan_table.add_column("Why", style="default", overflow="fold")
        plan_table.add_column("Scope", justify="center")
        for i, s in enumerate(steps, 1):
            blocked = ag.scope_blocks(s["module"])
            plan_table.add_row(
                str(i), s["module"], s.get("reason", "") or "—",
                f"[{ui.DANGER}]skip[/]" if blocked else f"[{ui.OK}]ok[/]",
            )
        console.print(plan_table)

        if dry_run:
            console.print("[dim]--dry-run: not executing. Re-run without it to proceed.[/dim]")
            return

        # 2) Confirm (active steps touch the target)
        if not yes:
            active = [s["module"] for s in steps
                      if s["module"] in ACTIVE_ACTIONS and not ag.scope_blocks(s["module"])]
            msg = ("This will actively scan the target"
                   if active else "This will run passive steps only")
            if not typer.confirm(f"{msg}. Proceed? (authorized targets only)", default=False):
                console.print("[yellow]Aborted.[/yellow]")
                return

        # 3) Execute
        findings = await ag.execute(engine, steps)

        # 4) Final assessment
        from spaf.utils import ui as _ui
        console.print()
        console.print(_ui.eyebrow("Agent Assessment"))
        if findings:
            sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for f in findings:
                sev[f.get("severity", "Info")] = sev.get(f.get("severity", "Info"), 0) + 1
            parts = [f"[{_ui.SEVERITY[k]}]{k} {v}[/]" for k, v in sev.items() if v]
            console.print(
                f"[bold]{len(findings)}[/bold] [dim]finding(s)[/dim]   " + "  ".join(parts)
            )
            summary = await ag.summarize()
            if summary:
                console.print(_ui.panel(summary, title=f"AI Assessment · {target}"))
        else:
            console.print(f"[{_ui.FAINT}]No findings produced.[/]")

        if output:
            with open(output, "w") as f:
                json.dump(findings, f, indent=4, default=str)
            console.print(f"[green]Findings saved to:[/green] {output}")

    asyncio.run(run())


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (default localhost; use 0.0.0.0 behind a gateway)"),
    port: int = typer.Option(8000, "--port", help="Port to listen on"),
    scope_file: str = typer.Option("scope.json", "--scope-file", help="Engagement scope file the API enforces"),
):
    """Run the SPAF HTTP API (REST + WebSocket live events)."""
    try:
        import uvicorn
        from spaf.api import create_app
    except ModuleNotFoundError:
        console.print(
            "[bold red]API support is not installed.[/bold red]\n"
            "[dim]Install it with:[/dim] [cyan]pip install \"spaf[api]\"[/cyan]"
        )
        raise typer.Exit(1)
    print_banner(compact=True)
    console.print(f"[dim]API on[/dim] [cyan]http://{host}:{port}[/cyan]  "
                  f"[dim]· docs at[/dim] [cyan]/docs[/cyan]  [dim]· set SPAF_API_KEYS, or watch stderr for a generated key.[/dim]")
    uvicorn.run(create_app(scope_file), host=host, port=port, log_level="info")


@app.command()
def mcp(
    scope_file: str = typer.Option("scope.json", "--scope-file", help="Engagement scope file the server enforces"),
):
    """Run SPAF as an MCP server (stdio) so Claude Desktop / MCP hosts can drive it."""
    try:
        from spaf.mcp.server import run as run_mcp
    except ModuleNotFoundError:
        console.print(
            "[bold red]MCP support is not installed.[/bold red]\n"
            "[dim]Install it with:[/dim] [cyan]pip install \"spaf[mcp]\"[/cyan]"
        )
        raise typer.Exit(1)
    # Do NOT print anything else to stdout here — stdio carries the MCP protocol.
    run_mcp(scope_file=scope_file)


@app.command(name="mcp-tools")
def mcp_tools(
    config: str = typer.Option("mcp_servers.json", "--config", help="External MCP servers config (Claude-Desktop shape)"),
    server: Optional[str] = typer.Option(None, "--server", help="Only this server"),
):
    """List tools from external MCP servers SPAF is configured to consume."""
    from spaf.utils import ui
    try:
        from spaf.mcp.client import MCPClientManager
    except ModuleNotFoundError:
        console.print("[bold red]MCP support not installed.[/bold red] [dim]pip install \"spaf[mcp]\"[/dim]")
        raise typer.Exit(1)

    mgr = MCPClientManager(config_path=config)
    if not mgr.names():
        console.print(f"[{ui.FAINT}]No external MCP servers configured in {config}.[/]")
        console.print(f"[{ui.FAINT}]Add them in Claude-Desktop shape: "
                      '{"mcpServers": {"name": {"command": "...", "args": ["..."]}}}[/]')
        return

    async def run():
        data = await (mgr.list_tools(server) if server else mgr.list_all_tools())
        servers = {server: data} if server else data
        for name, tools in servers.items():
            table = ui.table(f"MCP · {name}")
            table.add_column("Tool", style=ui.AMBER)
            table.add_column("Description", style="default", overflow="fold")
            for t in tools:
                table.add_row(t["name"], (t.get("description") or "")[:100])
            console.print(table)

    asyncio.run(run())


@app.command()
def plugins():
    """List SPAF scan-module plugins discovered via entry points or registration."""
    from spaf.utils import ui
    from spaf import plugins as plug
    mods = plug.registered_modules()
    if not mods:
        console.print(f"[{ui.FAINT}]No plugins registered.[/] "
                      f"[dim]Advertise a BaseModule under the 'spaf.modules' entry-point group.[/dim]")
        return
    table = ui.table("Plugins")
    table.add_column("Module", style=ui.AMBER)
    table.add_column("Class", style="default")
    for name, cls in sorted(mods.items()):
        table.add_row(name, f"{cls.__module__}.{cls.__name__}")
    console.print(table)


@app.command()
def engagements(
    create: Optional[str] = typer.Option(None, "--create", help="Create an engagement with this name"),
    scope: Optional[str] = typer.Option(None, "--scope", help="Comma-separated in-scope entries for --create"),
    authorized_by: Optional[str] = typer.Option(None, "--authorized-by", help="Sign an authorization from this party"),
    retention_days: int = typer.Option(0, "--retention-days", help="Days to keep results (0 = forever)"),
):
    """List engagement workspaces, or create one with --create (Phase 7)."""
    from spaf.utils import ui
    from spaf.workspaces import EngagementManager
    mgr = EngagementManager()

    if create:
        in_scope = [s.strip() for s in (scope or "").split(",") if s.strip()]
        eng = mgr.create(create, created_by="cli", in_scope=in_scope,
                         retention_days=retention_days,
                         authorized_by=authorized_by or None)
        console.print(f"[{ui.OK}]created[/] engagement [bold]{eng.id}[/] "
                      f"at [dim]{eng.storage_dir}[/dim]")
        if authorized_by:
            ok = mgr.authorization_valid(eng)
            console.print(f"  authorization: {'[green]signed & valid[/]' if ok else '[red]invalid[/]'}")
        return

    rows = mgr.list()
    if not rows:
        console.print(f"[{ui.FAINT}]No engagements yet.[/] "
                      f"[dim]Create one: spaf engagements --create 'Acme' --scope acme.com[/dim]")
        return
    table = ui.table("Engagements")
    table.add_column("ID", style=ui.AMBER)
    table.add_column("Name")
    table.add_column("Authorized")
    table.add_column("Retention")
    for e in rows:
        auth = "[green]yes[/]" if mgr.authorization_valid(e) else f"[{ui.FAINT}]no[/]"
        ret = f"{e.retention.days}d" if e.retention.days else "∞"
        table.add_row(e.id, e.name, auth, ret)
    console.print(table)


@app.command()
def report(
    target: Optional[str] = typer.Argument(None, help="Target to generate report for"),
    format: str = typer.Option("both", "--format", help="Report format: html|json|both"),
    output_dir: str = typer.Option("./reports", "--output-dir", help="Directory to save reports"),
    from_file: Optional[str] = typer.Option(None, "--from-file", help="Generate report from a local JSON results file"),
    with_ai: bool = typer.Option(False, "--with-ai", help="Embed an AI threat-intelligence analysis in the report"),
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
            
        ai_analysis = None
        if with_ai:
            with console.status("[bold magenta]AI is analyzing findings for the report…[/bold magenta]"):
                ai_analysis = await ai_orchestrator.analyze_findings(findings)

        meta = {"target": report_target, "total_findings": len(findings)}
        generator = ReportGenerator(report_target, findings, meta, ai_analysis=ai_analysis)
        
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

# ─────────────────────────────────────────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────────────────────────────────────────
@app.command()
def export(
    target: str = typer.Argument(..., help="Target domain/IP to export findings for"),
    format: str = typer.Option("csv",  "--format", help="Output format: csv | json"),
    output: str = typer.Option("",     "--output", help="Output file path (default: <target>_findings.<ext>)"),
):
    """Export all findings for a target to CSV or JSON for client deliverables."""
    import csv

    async def run():
        await _init_db()
        findings = await db.get_all_vulnerabilities_for_export(target)
        if not findings:
            console.print(f"[yellow]No findings found for target:[/yellow] {target}")
            return

        fmt   = format.lower()
        fname = output or f"{target.replace('.', '_')}_findings.{fmt}"

        # Sanitise ObjectId / datetime for serialisation
        clean = []
        for f in findings:
            row = {k: str(v) for k, v in f.items()}
            clean.append(row)

        if fmt == "json":
            with open(fname, "w", encoding="utf-8") as fh:
                json.dump(clean, fh, indent=2)
        elif fmt == "csv":
            if clean:
                fieldnames = list(clean[0].keys())
                with open(fname, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(clean)
        else:
            console.print(f"[red]Unknown format:[/red] {fmt}. Use 'csv' or 'json'.")
            return

        console.print(f"[bold green]✅ Exported {len(clean)} findings → {fname}[/bold green]")

    asyncio.run(run())


# ─────────────────────────────────────────────────────────────────────────────
# DIFF
# ─────────────────────────────────────────────────────────────────────────────
@app.command()
def diff(
    scan_a: str = typer.Argument(..., help="Older scan ID"),
    scan_b: str = typer.Argument(..., help="Newer scan ID"),
):
    """Compare two scans and show new, fixed, and unchanged findings."""
    async def run():
        await _init_db()

        meta_a = await db.get_scan_meta(scan_a)
        meta_b = await db.get_scan_meta(scan_b)

        if not meta_a:
            console.print(f"[red]Scan not found:[/red] {scan_a}"); return
        if not meta_b:
            console.print(f"[red]Scan not found:[/red] {scan_b}"); return

        findings_a = await db.get_vulnerabilities_for_scan(scan_a)
        findings_b = await db.get_vulnerabilities_for_scan(scan_b)

        keys_a = {f["vuln_type"] for f in findings_a}
        keys_b = {f["vuln_type"] for f in findings_b}

        new_vulns   = keys_b - keys_a
        fixed_vulns = keys_a - keys_b
        same_vulns  = keys_a & keys_b

        def ts(meta):
            return meta.get("started_at", "").strftime("%Y-%m-%d %H:%M") if hasattr(meta.get("started_at"), "strftime") else str(meta.get("started_at", ""))

        console.print(f"\n[bold]Scan Diff[/bold]  [dim]{ts(meta_a)}[/dim] → [dim]{ts(meta_b)}[/dim]")
        console.print(f"Target: [cyan]{meta_a.get('target')}[/cyan]\n")

        if new_vulns:
            t = Table(title=f"🆕 New Findings ({len(new_vulns)})", border_style="red")
            t.add_column("vuln_type", style="red")
            for k in sorted(new_vulns): t.add_row(k)
            console.print(t)

        if fixed_vulns:
            t = Table(title=f"✅ Fixed / Resolved ({len(fixed_vulns)})", border_style="green")
            t.add_column("vuln_type", style="green")
            for k in sorted(fixed_vulns): t.add_row(k)
            console.print(t)

        console.print(f"[dim]Unchanged: {len(same_vulns)} findings[/dim]")

    asyncio.run(run())


# ─────────────────────────────────────────────────────────────────────────────
# SCOPE
# ─────────────────────────────────────────────────────────────────────────────
@app.command()
def scope(
    action: str = typer.Argument(..., help="Action: show | add | remove"),
    value:  str = typer.Argument("",  help="Domain/IP/CIDR to add or remove"),
    scope_file: str = typer.Option("scope.json", "--file", help="Scope config file path"),
):
    """
    Manage engagement scope (in-scope targets and exclusions).

    \b
    spaf scope show
    spaf scope add target.com
    spaf scope remove target.com
    """
    from spaf.utils.scope import load_scope, save_scope

    data = load_scope(scope_file)
    act  = action.lower()

    if act == "show":
        t = Table(title=f"Engagement Scope ({scope_file})", show_header=True)
        t.add_column("In Scope",  style="green")
        t.add_column("Out of Scope", style="red")
        rows = max(len(data["in_scope"]), len(data["out_of_scope"]))
        for i in range(rows):
            t.add_row(
                data["in_scope"][i]     if i < len(data["in_scope"])     else "",
                data["out_of_scope"][i] if i < len(data["out_of_scope"]) else "",
            )
        console.print(t)

    elif act == "add":
        if not value:
            console.print("[red]Provide a value to add.[/red]"); return
        if value not in data["in_scope"]:
            data["in_scope"].append(value)
            save_scope(scope_file, data)
        console.print(f"[green]Added to scope:[/green] {value}")

    elif act == "remove":
        if value in data["in_scope"]:
            data["in_scope"].remove(value)
            save_scope(scope_file, data)
            console.print(f"[yellow]Removed from scope:[/yellow] {value}")
        else:
            console.print(f"[dim]{value} not found in scope.[/dim]")
    else:
        console.print(f"[red]Unknown action:[/red] {act}. Use: show | add | remove")


# ─────────────────────────────────────────────────────────────────────────────
# UPDATE
# ─────────────────────────────────────────────────────────────────────────────
@app.command()
def update():
    """Update SPAF to the latest version from PyPI."""
    import subprocess, sys

    console.print("[bold cyan]Checking for SPAF updates...[/bold cyan]")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "spaf"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            if any("Successfully installed" in l for l in lines):
                version_line = next((l for l in lines if "spaf" in l.lower()), "")
                console.print(f"[bold green]✅ SPAF updated successfully![/bold green]  {version_line}")
            else:
                console.print("[bold green]✅ SPAF is already up to date.[/bold green]")
        else:
            console.print(f"[bold red]Update failed:[/bold red]\n{result.stderr}")
    except Exception as exc:
        console.print(f"[bold red]Error running pip:[/bold red] {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def entry_point():
    load_plugins(app)
    app()

if __name__ == "__main__":
    entry_point()
