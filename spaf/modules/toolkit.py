"""
SPAF External Recon Toolkit
===========================

Wraps a suite of best-in-class open-source reconnaissance binaries into a single
chained pipeline that feeds each stage's output into the next:

    subfinder / assetfinder   → subdomain enumeration (passive)
    dnsx                      → DNS resolution / live-host filtering
    httpx                     → HTTP(S) probing (status, title, tech)
    katana / hakrawler        → active crawling of live hosts
    waybackurls / gau         → historical URL harvesting (passive)
    ffuf                      → content / directory fuzzing (needs wordlist)
    nuclei                    → template-based vulnerability scanning

Every binary is optional: if it is not on ``$PATH`` the stage is skipped with a
warning and an informational finding, so the pipeline degrades gracefully on a
partial install. Install the full suite with ``spaf toolkit --install-help``.

All external processes are launched with an argument list (never a shell string)
and the target is validated upstream, so target values cannot inject shell
commands.
"""

import asyncio
import json
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from rich.progress import Progress
from rich.table import Table

from spaf.core.engine import BaseModule
from spaf.utils.risk import build_finding
from spaf.utils.logger import logger
from spaf.utils.scope import is_in_scope

# Reference metadata for every supported binary (used by `spaf tools`).
TOOL_REGISTRY: Dict[str, Dict[str, str]] = {
    "subfinder":   {"role": "Passive subdomain enumeration",      "url": "https://github.com/projectdiscovery/subfinder"},
    "assetfinder": {"role": "Passive subdomain/asset discovery",  "url": "https://github.com/tomnomnom/assetfinder"},
    "dnsx":        {"role": "Fast DNS resolver / toolkit",        "url": "https://github.com/projectdiscovery/dnsx"},
    "httpx":       {"role": "HTTP(S) probing & fingerprinting",   "url": "https://github.com/projectdiscovery/httpx"},
    "katana":      {"role": "Next-gen crawling & spidering",      "url": "https://github.com/projectdiscovery/katana"},
    "hakrawler":   {"role": "Fast endpoint crawler",             "url": "https://github.com/hakluke/hakrawler"},
    "waybackurls": {"role": "Wayback Machine URL harvesting",     "url": "https://github.com/tomnomnom/waybackurls"},
    "gau":         {"role": "getallurls historical URL fetch",    "url": "https://github.com/lc/gau"},
    "ffuf":        {"role": "Content / directory fuzzing",        "url": "https://github.com/ffuf/ffuf"},
    "nuclei":      {"role": "Template-based vulnerability scan",  "url": "https://github.com/projectdiscovery/nuclei"},
}

# `go install` specifications for the Go-based tools (used by `spaf tools --install`).
GO_INSTALL: Dict[str, str] = {
    "subfinder":   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx":       "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei":      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "katana":      "github.com/projectdiscovery/katana/cmd/katana@latest",
    "dnsx":        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "hakrawler":   "github.com/hakluke/hakrawler@latest",
    "gau":         "github.com/lc/gau/v2/cmd/gau@latest",
    "ffuf":        "github.com/ffuf/ffuf/v2@latest",
}

# Map nuclei severities onto SPAF severities.
_NUCLEI_SEVERITY = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
    "unknown":  "Info",
}


class ToolkitModule(BaseModule):
    """Chained external-tool reconnaissance pipeline."""

    async def run(self, progress: Progress) -> List[Dict[str, Any]]:
        domain = self._domain()
        findings: List[Dict[str, Any]] = []

        # Which stages to run (all on by default; toggled from CLI options).
        do_subs   = self.options.get("subs", True)
        do_probe  = self.options.get("probe", True)
        do_crawl  = self.options.get("crawl", True)
        do_urls   = self.options.get("urls", True)
        do_fuzz   = self.options.get("fuzz", False)   # off by default (needs wordlist)
        do_nuclei = self.options.get("nuclei", True)

        task = progress.add_task(f"[green]Recon toolkit pipeline on {domain}...", total=100)

        # ── Stage 1: subdomain enumeration ────────────────────────────────
        hosts = {domain}
        if do_subs:
            progress.update(task, description="[cyan]Enumerating subdomains (subfinder, assetfinder)...", completed=5)
            subs, sub_findings = await self._enumerate_subdomains(domain)
            hosts.update(subs)
            findings.extend(sub_findings)
            if subs:
                findings.append(build_finding(
                    domain, "subdomains_enumerated",
                    f"External tools discovered {len(subs)} subdomain(s).",
                    "Info", "Review each subdomain for unintended exposure.",
                    "toolkit", extra={"count": len(subs), "sample": sorted(subs)[:25]},
                ))
        progress.update(task, completed=20)

        # ── Scope enforcement ─────────────────────────────────────────────
        # Passive enumeration may surface hosts outside the engagement scope
        # (e.g. third-party subdomains). Filter them out before any active
        # stage (probing, crawling, fuzzing, nuclei) touches them.
        scope = self.options.get("scope")
        if scope:
            in_scope = {h for h in hosts if is_in_scope(h, scope)}
            dropped = hosts - in_scope
            if dropped:
                findings.append(build_finding(
                    domain, "hosts_excluded_by_scope",
                    f"{len(dropped)} discovered host(s) were skipped as out-of-scope.",
                    "Info", "Add them to the engagement scope to include them in active scans.",
                    "toolkit", extra={"count": len(dropped), "sample": sorted(dropped)[:25]},
                ))
                logger.info(f"toolkit: {len(dropped)} host(s) dropped by scope filter.")
            hosts = in_scope or {domain}

        # ── Stage 2: DNS resolution ───────────────────────────────────────
        if self._available("dnsx") and len(hosts) > 1:
            progress.update(task, description="[cyan]Resolving hosts (dnsx)...")
            dnsx_out = await self._run_tool_stdin(
                "dnsx", ["dnsx", "-silent", "-a", "-resp-only"], "\n".join(sorted(hosts))
            )
            live = {line.strip() for line in dnsx_out if line.strip()}
            if live:
                findings.append(build_finding(
                    domain, "dns_resolved_hosts",
                    f"dnsx resolved {len(live)} record(s) across the discovered hosts.",
                    "Info", "Confirm ownership of every resolving asset.",
                    "toolkit", extra={"count": len(live)},
                ))
        progress.update(task, completed=35)

        # ── Stage 3: HTTP probing ─────────────────────────────────────────
        live_urls: List[str] = []
        if do_probe:
            progress.update(task, description="[cyan]Probing live web hosts (httpx)...")
            live_urls, probe_findings = await self._probe_http(domain, sorted(hosts))
            findings.extend(probe_findings)
        progress.update(task, completed=55)

        # Seed a base URL if probing was skipped or found nothing.
        if not live_urls:
            live_urls = [self.target if self.target.startswith("http") else f"https://{domain}"]

        # ── Stage 4: crawling ─────────────────────────────────────────────
        url_corpus: set = set()
        if do_crawl:
            progress.update(task, description="[cyan]Crawling live hosts (katana, hakrawler)...")
            url_corpus.update(await self._crawl(live_urls))
        progress.update(task, completed=70)

        # ── Stage 5: historical URL harvesting ────────────────────────────
        if do_urls:
            progress.update(task, description="[cyan]Harvesting historical URLs (waybackurls, gau)...")
            url_corpus.update(await self._historical_urls(domain))
        progress.update(task, completed=80)

        if url_corpus:
            findings.append(build_finding(
                domain, "url_corpus_collected",
                f"Collected {len(url_corpus)} unique URL(s) from crawling and archives.",
                "Info", "Feed interesting endpoints into targeted testing (fuzzing, injection).",
                "toolkit", extra={"count": len(url_corpus), "sample": sorted(url_corpus)[:25]},
            ))

        # ── Stage 6: content fuzzing (opt-in) ─────────────────────────────
        if do_fuzz:
            progress.update(task, description="[cyan]Fuzzing content (ffuf)...")
            findings.extend(await self._fuzz(domain, live_urls))
        progress.update(task, completed=90)

        # ── Stage 7: nuclei vulnerability scanning ────────────────────────
        if do_nuclei:
            progress.update(task, description="[cyan]Scanning for vulnerabilities (nuclei)...")
            # Feed nuclei the probed live hosts PLUS the crawled/historical URL
            # corpus (in-scope only) so DAST/fuzzing templates reach real
            # endpoints, not just site roots. Capped to keep scans bounded.
            scope = self.options.get("scope")
            corpus = [u for u in url_corpus if not scope or is_in_scope(u, scope)]
            cap = self.options.get("nuclei_url_cap", 2000)
            targets = list(dict.fromkeys([*live_urls, *sorted(corpus)]))[:cap]
            findings.extend(await self._nuclei(domain, targets))
        progress.update(task, completed=100)

        return findings

    # ------------------------------------------------------------------
    # Stage implementations
    # ------------------------------------------------------------------

    async def _enumerate_subdomains(self, domain: str):
        subs: set = set()
        findings: List[Dict[str, Any]] = []

        if self._available("subfinder"):
            out = await self._run_tool("subfinder", ["subfinder", "-d", domain, "-silent"])
            subs.update(s.strip().lower() for s in out if s.strip())
        else:
            findings.append(self._missing_tool_finding(domain, "subfinder"))

        if self._available("assetfinder"):
            out = await self._run_tool("assetfinder", ["assetfinder", "--subs-only", domain])
            subs.update(
                s.strip().lower() for s in out
                if s.strip() and s.strip().endswith(domain)
            )
        else:
            findings.append(self._missing_tool_finding(domain, "assetfinder"))

        subs.discard(domain)
        return subs, findings

    async def _probe_http(self, domain: str, hosts: List[str]):
        findings: List[Dict[str, Any]] = []
        if not self._available("httpx"):
            return [], [self._missing_tool_finding(domain, "httpx")]

        out = await self._run_tool_stdin(
            "httpx",
            ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code", "-no-color"],
            "\n".join(hosts),
        )

        live_urls: List[str] = []
        for line in out:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = rec.get("url") or rec.get("input")
            if not url:
                continue
            live_urls.append(url)
            status = rec.get("status_code") or rec.get("status-code")
            title = rec.get("title", "")
            tech = rec.get("tech") or rec.get("technologies") or []
            findings.append(build_finding(
                url, "live_web_host",
                f"Live host — status {status}"
                + (f", title '{title}'" if title else "")
                + (f", tech: {', '.join(tech)}" if tech else ""),
                "Info", "Enumerate the application and review the technology stack for known CVEs.",
                "toolkit", extra={"status": status, "title": title, "tech": tech},
            ))
        return live_urls, findings

    async def _crawl(self, live_urls: List[str]) -> set:
        urls: set = set()

        if self._available("katana"):
            # katana reads a target list from stdin when given `-list -`.
            out = await self._run_tool_stdin(
                "katana",
                ["katana", "-silent", "-list", "-", "-jc",
                 "-d", str(self.options.get("depth", 2))],
                "\n".join(live_urls),
            )
            urls.update(u.strip() for u in out if u.strip())

        if self._available("hakrawler"):
            out = await self._run_tool_stdin(
                "hakrawler", ["hakrawler", "-subs", "-u"], "\n".join(live_urls)
            )
            urls.update(u.strip() for u in out if u.strip().startswith("http"))

        return urls

    async def _historical_urls(self, domain: str) -> set:
        urls: set = set()

        if self._available("waybackurls"):
            out = await self._run_tool_stdin("waybackurls", ["waybackurls"], domain)
            urls.update(u.strip() for u in out if u.strip().startswith("http"))

        if self._available("gau"):
            out = await self._run_tool("gau", ["gau", "--subs", domain])
            urls.update(u.strip() for u in out if u.strip().startswith("http"))

        return urls

    async def _fuzz(self, domain: str, live_urls: List[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        wordlist = self.options.get("wordlist")

        if not self._available("ffuf"):
            return [self._missing_tool_finding(domain, "ffuf")]
        if not wordlist or not os.path.isfile(wordlist):
            logger.warning("ffuf stage skipped: provide a valid --wordlist to enable content fuzzing.")
            return [build_finding(
                domain, "fuzzing_skipped",
                "Content fuzzing (ffuf) skipped — no valid wordlist supplied.",
                "Info", "Re-run with --fuzz --wordlist <path> to enable directory brute-forcing.",
                "toolkit",
            )]

        base = live_urls[0].rstrip("/")
        with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tmp:
            out_path = tmp.name
        try:
            await self._run_tool(
                "ffuf",
                ["ffuf", "-u", f"{base}/FUZZ", "-w", wordlist,
                 "-mc", "200,204,301,302,307,401,403",
                 "-of", "json", "-o", out_path, "-s"],
            )
            findings.extend(self._parse_ffuf(out_path, base))
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass
        return findings

    def _parse_ffuf(self, out_path: str, base: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            with open(out_path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return findings

        for res in data.get("results", []):
            url = res.get("url", base)
            status = res.get("status")
            findings.append(build_finding(
                url, "content_discovered",
                f"ffuf discovered endpoint (HTTP {status}): {url}",
                "Low", "Review the discovered path for sensitive functionality or data exposure.",
                "toolkit", extra={"status": status, "length": res.get("length")},
            ))
        return findings

    async def _nuclei(self, domain: str, targets: List[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not self._available("nuclei"):
            return [self._missing_tool_finding(domain, "nuclei")]
        if not targets:
            return findings

        severity = self.options.get("nuclei_severity", "critical,high,medium")
        cmd = ["nuclei", "-silent", "-jsonl", "-severity", severity]
        # DAST mode runs fuzzing templates against the URL corpus (query params,
        # paths) — the workflow that finds injection on real endpoints.
        if self.options.get("nuclei_dast"):
            cmd.append("-dast")
        out = await self._run_tool_stdin("nuclei", cmd, "\n".join(targets))

        for line in out:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = rec.get("info", {})
            sev = _NUCLEI_SEVERITY.get(str(info.get("severity", "info")).lower(), "Info")
            matched = rec.get("matched-at") or rec.get("host") or domain
            name = info.get("name", rec.get("template-id", "nuclei-finding"))
            findings.append(build_finding(
                matched, f"nuclei:{rec.get('template-id', 'unknown')}",
                f"{name} — {info.get('description', '')}".strip(" —"),
                sev,
                "; ".join(info.get("remediation", "").splitlines()) or
                "Review the nuclei template reference and apply the recommended fix.",
                "toolkit",
                extra={
                    "template_id": rec.get("template-id"),
                    "matched_at": matched,
                    "tags": info.get("tags", []),
                    "reference": info.get("reference", []),
                },
            ))
        return findings

    # ------------------------------------------------------------------
    # Subprocess helpers
    # ------------------------------------------------------------------

    def _available(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    async def _run_tool(self, name: str, args: List[str], timeout: int = 300) -> List[str]:
        """Run an external tool with an argument list; return stdout lines."""
        return await self._exec(name, args, stdin_data=None, timeout=timeout)

    async def _run_tool_stdin(self, name: str, args: List[str], stdin_data: str,
                              timeout: int = 300) -> List[str]:
        """Run an external tool, piping ``stdin_data`` to it; return stdout lines."""
        return await self._exec(name, args, stdin_data=stdin_data, timeout=timeout)

    async def _exec(self, name: str, args: List[str], stdin_data: Optional[str],
                    timeout: int) -> List[str]:
        logger.debug(f"toolkit exec: {' '.join(args)}")
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.warning(f"{name} binary not found on PATH — stage skipped.")
            return []

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=stdin_data.encode() if stdin_data is not None else None),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            logger.warning(f"{name} timed out after {timeout}s — stage skipped.")
            return []

        if process.returncode not in (0, None) and not stdout:
            logger.debug(f"{name} exited {process.returncode}: {stderr.decode(errors='ignore').strip()}")
        return stdout.decode(errors="ignore").splitlines()

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------

    def _domain(self) -> str:
        raw = self.target
        if raw.startswith("http"):
            return urlparse(raw).netloc or raw
        return raw.split("/")[0]

    def _missing_tool_finding(self, domain: str, tool: str) -> Dict[str, Any]:
        meta = TOOL_REGISTRY.get(tool, {})
        return build_finding(
            domain, "tool_not_installed",
            f"'{tool}' is not installed — {meta.get('role', 'stage')} was skipped.",
            "Info",
            f"Install {tool} to enable this stage: {meta.get('url', '')}".strip(),
            "toolkit", extra={"tool": tool},
        )

    def render_results(self, results: List[Dict[str, Any]]):
        if not results:
            self.console.print("[yellow]No findings produced by the recon toolkit.[/yellow]")
            return

        table = Table(title="Recon Toolkit Findings")
        table.add_column("Target", style="cyan", overflow="fold")
        table.add_column("Type", style="magenta")
        table.add_column("Severity", style="bold")
        table.add_column("Detail", style="white", overflow="fold")

        order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5}
        for r in sorted(results, key=lambda x: order.get(x["severity"], 9)):
            sev = r["severity"]
            color = ("red" if sev == "Critical" else "orange3" if sev == "High"
                     else "yellow" if sev == "Medium" else "cyan" if sev == "Low" else "dim white")
            table.add_row(
                r["target"][:60], r["vuln_type"],
                f"[{color}]{sev}[/{color}]", r["detail"][:90],
            )
        self.console.print(table)
