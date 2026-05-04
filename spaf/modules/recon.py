import asyncio
import aiohttp
import socket
import dns.resolver
import dns.zone
import dns.query
import whois
from typing import Any, Dict, List
from rich.table import Table
from rich.progress import Progress

from spaf.core.engine import BaseModule
from spaf.utils.risk import build_finding
from spaf.utils.logger import logger

class ReconModule(BaseModule):
    COMMON_SUBDOMAINS = ["dev", "staging", "test", "prod", "vpn", "admin", "mail", "remote", "api", "git", "cloud", "portal"]

    async def run(self, progress: Progress) -> List[Dict[str, Any]]:
        task = progress.add_task("[green]Starting passive reconnaissance...", total=100)
        findings = []
        
        domain = self.target
        is_passive = self.options.get("passive", False)

        # 1. Subdomain Enumeration via crt.sh
        progress.update(task, description="[cyan]Enumerating subdomains via crt.sh...", completed=10)
        subdomains = await self._get_subdomains(domain)
        
        # 1b. Active Subdomain Brute-force (if enabled)
        if not is_passive:
            progress.update(task, description="[cyan]Brute-forcing common subdomains...", completed=20)
            brute_subs = [f"{s}.{domain}" for s in self.COMMON_SUBDOMAINS]
            subdomains = list(set(subdomains + brute_subs))
            
        progress.update(task, completed=30)

        # 2. DNS Resolution (Limit to 100)
        progress.update(task, description=f"[cyan]Resolving {min(len(subdomains), 100)} subdomains...")
        resolved_subs = await self._resolve_subdomains(subdomains[:100])
        progress.update(task, completed=50)

        # 3. DNS Record Fetching
        progress.update(task, description="[cyan]Fetching DNS records (A, MX, NS, TXT)...")
        dns_records = await self._get_dns_records(domain)
        progress.update(task, completed=70)

        # 4. WHOIS Lookup
        progress.update(task, description="[cyan]Performing WHOIS lookup...")
        whois_info = await self._get_whois_info(domain)
        progress.update(task, completed=90)

        # 5. Analyze Findings
        findings.extend(self._analyze_dns(domain, dns_records))
        findings.extend(self._analyze_whois(domain, whois_info))
        
        # 6. Active Checks (Zone Transfer)
        if not is_passive and dns_records.get("NS"):
            progress.update(task, description="[cyan]Attempting DNS zone transfer (AXFR)...", completed=95)
            findings.extend(await self._attempt_zone_transfer(domain, dns_records["NS"]))
        
        if len(resolved_subs) > 20:
            findings.append(build_finding(
                domain, "large_subdomain_attack_surface",
                f"Identified {len(resolved_subs)} live subdomains.",
                "Low", "Consider reviewing subdomains for unnecessary exposure.",
                "recon", extra={"count": len(resolved_subs)}
            ))

        progress.update(task, completed=100)
        return findings

    async def _get_subdomains(self, domain: str) -> List[str]:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains = set()
        try:
            async with self.get_session() as session:
                async with session.get(url, timeout=30, **self.get_request_params()) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split('\n'):
                                if sub.endswith(domain) and '*' not in sub:
                                    subdomains.add(sub.lower())
        except Exception as e:
            logger.error(f"crt.sh error: {e}")
        return sorted(list(subdomains))

    async def _resolve_subdomains(self, subdomains: List[str]) -> List[str]:
        concurrency = self.options.get("concurrency", 10)
        delay = self.options.get("delay", 0.0)
        semaphore = asyncio.Semaphore(concurrency)
        resolved = []

        async def resolve(sub):
            async with semaphore:
                if delay > 0:
                    await asyncio.sleep(delay)
                try:
                    # get_running_loop() is correct inside a running coroutine
                    loop = asyncio.get_running_loop()
                    await loop.getaddrinfo(sub, None)
                    resolved.append(sub)
                except Exception:
                    pass

        await asyncio.gather(*(resolve(sub) for sub in subdomains))
        return resolved

    async def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        records = {}
        types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        for rtype in types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        return records

    async def _attempt_zone_transfer(self, domain: str, ns_records: List[str]) -> List[Dict[str, Any]]:
        findings = []
        for ns in ns_records:
            try:
                loop  = asyncio.get_running_loop()
                ns_ip = socket.gethostbyname(ns)
                z = await loop.run_in_executor(None, dns.zone.from_xfr, dns.query.xfr(ns_ip, domain))
                if z:
                    findings.append(build_finding(
                        domain, "dns_zone_transfer_enabled",
                        f"DNS zone transfer enabled on {ns} ({ns_ip}). Significant information exposure.",
                        "Critical", f"Disable AXFR zone transfers on the name server {ns}.",
                        "recon"
                    ))
            except Exception:
                pass
        return findings

    async def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        try:
            # whois is blocking — offload to thread pool
            loop = asyncio.get_running_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            return dict(w)
        except Exception as e:
            logger.error(f"WHOIS error: {e}")
            return {}

    def _analyze_dns(self, domain: str, records: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        findings = []
        txt_records = "".join(records.get("TXT", [])).lower()
        
        if "v=spf1" not in txt_records:
            findings.append(build_finding(
                domain, "missing_spf_record",
                "No SPF record found in DNS TXT records.",
                "Medium", "Implement a valid SPF record (v=spf1) to prevent email spoofing.",
                "recon"
            ))
            
        if "v=dmarc1" not in txt_records:
            findings.append(build_finding(
                domain, "missing_dmarc_record",
                "No DMARC record found in DNS TXT records.",
                "Medium", "Implement a DMARC policy (v=DMARC1) to handle email authentication failures.",
                "recon"
            ))
            
        return findings

    def _analyze_whois(self, domain: str, info: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        emails = info.get("emails", [])
        if emails:
            if isinstance(emails, str): emails = [emails]
            findings.append(build_finding(
                domain, "info_exposure_whois_email",
                f"WHOIS record exposes registrant emails: {', '.join(emails)}",
                "Low", "Enable WHOIS privacy protection (Redaction) via your registrar.",
                "recon", extra={"emails": emails}
            ))
        return findings

    def render_results(self, results: List[Dict[str, Any]]):
        if not results:
            self.console.print("[yellow]No security findings identified in recon.[/yellow]")
            return

        table = Table(title="Passive Reconnaissance Findings")
        table.add_column("Type", style="cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Detail", style="white")

        for r in results:
            sev = r['severity']
            color = "red" if sev == "Critical" else "orange3" if sev == "High" else "yellow" if sev == "Medium" else "cyan"
            table.add_row(r['vuln_type'], f"[{color}]{sev}[/{color}]", r['detail'])

        self.console.print(table)
