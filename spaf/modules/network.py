import asyncio
import os
import aiohttp
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from rich.table import Table
from rich.progress import Progress

from spaf.core.engine import BaseModule
from spaf.utils.risk import build_finding
from spaf.utils.logger import logger

# ---------------------------------------------------------------------------
# NVD API rate limiting
# Public:  5 req / 30 s  → 1 req every 6.5 s (conservative)
# API key: 50 req / 30 s → 1 req every 0.65 s
# Set NIST_API_KEY in .env to increase throughput.
# ---------------------------------------------------------------------------
_NVD_API_KEY   = os.getenv("NIST_API_KEY", "")
_NVD_REQ_DELAY = 0.65 if _NVD_API_KEY else 6.5   # seconds between NVD requests
# Semaphore created lazily inside the first coroutine that needs it
_nvd_semaphore: asyncio.Semaphore | None = None


def _get_nvd_semaphore() -> asyncio.Semaphore:
    """Return (and lazily create) the module-level NVD semaphore."""
    global _nvd_semaphore
    if _nvd_semaphore is None:
        _nvd_semaphore = asyncio.Semaphore(1)  # one NVD request at a time
    return _nvd_semaphore


class NetworkModule(BaseModule):
    # Port to Severity/Recommendation mapping
    RISKY_PORTS = {
        21:    ("Medium",   "FTP service detected. Ensure it uses FTPS or is disabled if unnecessary."),
        23:    ("High",     "Telnet service detected. Replace with SSH (encrypted)."),
        445:   ("Critical", "SMB service detected. Ensure it is not exposed to the internet and is patched against EternalBlue/etc."),
        135:   ("High",     "RPC service detected. Potential for information disclosure or exploitation."),
        139:   ("High",     "NetBIOS service detected. Potential for information gathering."),
        1433:  ("Critical", "MSSQL service detected. Ensure strong authentication and restrict access."),
        1521:  ("Critical", "Oracle DB service detected. Ensure strong authentication and restrict access."),
        3306:  ("Critical", "MySQL service detected. Ensure it is not publicly accessible and has strong credentials."),
        5432:  ("Critical", "PostgreSQL service detected. Ensure it is not publicly accessible and has strong credentials."),
        6379:  ("Critical", "Redis service detected. Redis is often unauthenticated by default; ensure it is secured."),
        27017: ("Critical", "MongoDB service detected. Ensure authentication is enabled and access is restricted."),
        3389:  ("High",     "RDP service detected. Ensure it uses NLA and is not publicly accessible."),
        5900:  ("High",     "VNC service detected. Ensure it is encrypted and requires strong authentication."),
        4444:  ("Critical", "Metasploit/Shell service detected. High indication of compromise or open backdoor."),
    }

    async def run(self, progress: Progress) -> List[Dict[str, Any]]:
        scanner  = self.options.get("scanner", "nmap")
        intensity = self.options.get("intensity", "normal")
        ports    = self.options.get("ports", "1-1024")

        if scanner == "rustscan":
            return await self._run_rustscan(progress, intensity, ports)
        return await self._run_nmap(progress, intensity, ports)

    # ------------------------------------------------------------------
    # Nmap engine
    # ------------------------------------------------------------------

    async def _run_nmap(self, progress: Progress, intensity: str, ports: str) -> List[Dict[str, Any]]:
        nmap_args = self._get_nmap_args(intensity, ports)
        task = progress.add_task(
            f"[green]Running Nmap ({intensity}) on {self.target}...", total=100
        )
        try:
            cmd = f"nmap -oX - {nmap_args} {self.target}"
            logger.debug(f"Executing: {cmd}")

            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Nmap failed: {stderr.decode()}")
                return []

            progress.update(task, completed=80, description="[cyan]Parsing Nmap XML output...")
            findings = self._parse_nmap_xml(stdout.decode())
            findings = await self._enrich_with_cves(findings, intensity, progress, task)
            progress.update(task, completed=100)
            return findings

        except Exception as e:
            logger.error(f"Network scan error: {e}")
            return []

    # ------------------------------------------------------------------
    # RustScan engine
    #
    # RustScan blasts through all ports at high speed using async TCP
    # connects, then passes discovered open ports directly to Nmap for
    # service / OS / script detection.
    #
    # Usage in SPAF:
    #   spaf scan <target> --scanner rustscan [--ports 1-65535]
    #                      [--ulimit 5000] [--batch-size 2500]
    #                      [--intensity normal]
    # ------------------------------------------------------------------

    async def _run_rustscan(self, progress: Progress, intensity: str, ports: str) -> List[Dict[str, Any]]:
        ulimit     = self.options.get("ulimit", 5000)
        batch_size = self.options.get("batch_size", 2500)
        nmap_args  = self._get_nmap_args_for_rustscan(intensity)

        task = progress.add_task(
            f"[green]Running RustScan ({intensity}) on {self.target}...", total=100
        )
        try:
            # RustScan discovers open ports, then invokes Nmap with -p <ports>.
            # Passing -oX - after -- tells Nmap to write XML to stdout,
            # which RustScan forwards to its own stdout.
            cmd = (
                f"rustscan -a {self.target} "
                f"--ulimit {ulimit} "
                f"--batch-size {batch_size} "
                f"--range {ports} "
                f"-- {nmap_args} -oX -"
            )
            logger.debug(f"Executing: {cmd}")

            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            progress.update(task, completed=30, description="[cyan]RustScan discovering open ports...")
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"RustScan failed (exit {process.returncode}): {stderr.decode().strip()}")
                return []

            progress.update(task, completed=75, description="[cyan]Parsing RustScan/Nmap XML output...")

            xml_output = self._extract_nmap_xml(stdout.decode())
            if not xml_output:
                logger.warning(
                    "RustScan produced no Nmap XML. Either no open ports were found "
                    "or 'rustscan' is not installed (https://github.com/RustScan/RustScan)."
                )
                return []

            findings = self._parse_nmap_xml(xml_output)
            findings = await self._enrich_with_cves(findings, intensity, progress, task)
            progress.update(task, completed=100)
            return findings

        except FileNotFoundError:
            logger.error(
                "RustScan binary not found. "
                "Install it from https://github.com/RustScan/RustScan"
            )
            return []
        except Exception as e:
            logger.error(f"RustScan error: {e}")
            return []

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _get_nmap_args(self, intensity: str, ports: str) -> str:
        """Nmap args with explicit port range (used for standalone Nmap runs)."""
        profiles = {
            "light":      f"-T2 -F -p {ports} --open",
            "normal":     f"-T3 -sV -O -p {ports} --open --osscan-limit",
            "aggressive": f"-T4 -sV -sC -O -A -p {ports} --open",
        }
        return profiles.get(intensity, profiles["normal"])

    def _get_nmap_args_for_rustscan(self, intensity: str) -> str:
        """Nmap args WITHOUT a port range — RustScan injects -p <ports> itself."""
        profiles = {
            "light":      "-T2 --open",
            "normal":     "-T3 -sV -O --open --osscan-limit",
            "aggressive": "-T4 -sV -sC -O -A --open",
        }
        return profiles.get(intensity, profiles["normal"])

    def _extract_nmap_xml(self, raw_output: str) -> str:
        """
        RustScan mixes its own status banners with the Nmap XML block on stdout.
        Extract just the XML portion (everything from <?xml or <nmaprun onwards).
        """
        for marker in ("<?xml", "<nmaprun"):
            idx = raw_output.find(marker)
            if idx != -1:
                return raw_output[idx:]
        return ""

    async def _enrich_with_cves(
        self,
        findings: List[Dict[str, Any]],
        intensity: str,
        progress: Progress,
        task,
    ) -> List[Dict[str, Any]]:
        """NVD CVE lookups for identified products/versions (skipped on light scans)."""
        if intensity == "light":
            return findings

        progress.update(task, completed=90, description="[cyan]Performing CVE lookups for services...")
        for finding in findings:
            extra   = finding.get("extra", {})
            product = extra.get("product")
            version = extra.get("version")
            if product and version and product != "unknown":
                cves = await self._lookup_cves(product, version)
                if cves:
                    extra["cves"] = cves
                    finding["detail"] += f" | Known CVEs: {', '.join(cves)}"
                    if finding["severity"] not in ["Critical", "High"]:
                        finding["severity"] = "High"
        return findings

    def _parse_nmap_xml(self, xml_data: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            root = ET.fromstring(xml_data)
            host  = root.find("host")
            if host is None:
                return []

            os_match = host.find(".//osmatch")
            os_name  = os_match.get("name") if os_match is not None else "Unknown"

            for port_elem in host.findall(".//port"):
                port_id  = int(port_elem.get("portid"))
                protocol = port_elem.get("protocol")
                state    = port_elem.find("state").get("state")

                service_elem = port_elem.find("service")
                service_name = service_elem.get("name")             if service_elem is not None else "unknown"
                product      = service_elem.get("product", "unknown") if service_elem is not None else "unknown"
                version      = service_elem.get("version", "unknown") if service_elem is not None else "unknown"

                if state == "open":
                    if port_id in self.RISKY_PORTS:
                        severity, rec = self.RISKY_PORTS[port_id]
                        findings.append(build_finding(
                            self.target, "risky_port_exposed",
                            f"Port {port_id} ({service_name}) is open. Product: {product} {version}",
                            severity, rec, "network",
                            extra={
                                "port": port_id, "protocol": protocol,
                                "service": service_name, "product": product,
                                "version": version, "os": os_name,
                            },
                        ))
                    else:
                        findings.append(build_finding(
                            self.target, "open_port",
                            f"Port {port_id} ({service_name}) is open.",
                            "Info", "Review if this port needs to be exposed.",
                            "network",
                            extra={"port": port_id, "service": service_name},
                        ))
        except Exception as e:
            logger.error(f"XML Parsing error: {e}")
        return findings

    async def _lookup_cves(self, product: str, version: str) -> List[str]:
        if product == "unknown" or version == "unknown":
            return []

        query    = f"{product} {version}"
        url      = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
        headers  = {"apiKey": _NVD_API_KEY} if _NVD_API_KEY else {}
        cve_list = []

        async with _get_nvd_semaphore():
            try:
                async with self.get_session() as session:
                    async with session.get(
                        url, timeout=15, headers=headers, **self.get_request_params()
                    ) as resp:
                        if resp.status == 429:
                            logger.warning(
                                "NVD API rate limit hit — sleeping 30 s then retrying. "
                                "Set NIST_API_KEY in .env for higher throughput."
                            )
                            await asyncio.sleep(30)
                            # Single retry after backoff
                            async with session.get(
                                url, timeout=15, headers=headers, **self.get_request_params()
                            ) as retry_resp:
                                if retry_resp.status == 200:
                                    data = await retry_resp.json()
                                    for v in data.get("vulnerabilities", [])[:5]:
                                        cve_id = v.get("cve", {}).get("id")
                                        if cve_id:
                                            cve_list.append(cve_id)
                        elif resp.status == 200:
                            data = await resp.json()
                            for v in data.get("vulnerabilities", [])[:5]:
                                cve_id = v.get("cve", {}).get("id")
                                if cve_id:
                                    cve_list.append(cve_id)
                        else:
                            logger.debug(f"NVD returned HTTP {resp.status} for '{query}'")
            except Exception as e:
                logger.error(f"CVE Lookup failed: {e}")
            finally:
                # Enforce delay AFTER releasing the semaphore so other callers
                # wait the full window before their own request.
                await asyncio.sleep(_NVD_REQ_DELAY)

        return cve_list

    def render_results(self, results: List[Dict[str, Any]]):
        if not results:
            self.console.print("[yellow]No open ports found or scan failed.[/yellow]")
            return

        table = Table(title=f"Network Scan Results for {self.target}")
        table.add_column("Port",     style="cyan")
        table.add_column("Service",  style="magenta")
        table.add_column("Product",  style="green")
        table.add_column("Severity", style="bold")

        for r in results:
            extra   = r.get("extra", {})
            port    = extra.get("port", "N/A")
            service = extra.get("service", "unknown")
            product = extra.get("product", "unknown")
            sev     = r["severity"]
            color   = (
                "red"       if sev == "Critical" else
                "orange3"   if sev == "High"     else
                "yellow"    if sev == "Medium"   else
                "cyan"      if sev == "Low"       else
                "dim white"
            )
            table.add_row(str(port), service, product, f"[{color}]{sev}[/{color}]")

        self.console.print(table)
