import asyncio
import aiohttp
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from rich.table import Table
from rich.progress import Progress

from spaf.core.engine import BaseModule
from spaf.utils.risk import build_finding
from spaf.utils.logger import logger

class NetworkModule(BaseModule):
    # Port to Severity/Recommendation mapping
    RISKY_PORTS = {
        21: ("Medium", "FTP service detected. Ensure it uses FTPS or is disabled if unnecessary."),
        23: ("High", "Telnet service detected. Replace with SSH (encrypted)."),
        445: ("Critical", "SMB service detected. Ensure it is not exposed to the internet and is patched against EternalBlue/etc."),
        135: ("High", "RPC service detected. Potential for information disclosure or exploitation."),
        139: ("High", "NetBIOS service detected. Potential for information gathering."),
        1433: ("Critical", "MSSQL service detected. Ensure strong authentication and restrict access."),
        1521: ("Critical", "Oracle DB service detected. Ensure strong authentication and restrict access."),
        3306: ("Critical", "MySQL service detected. Ensure it is not publicly accessible and has strong credentials."),
        5432: ("Critical", "PostgreSQL service detected. Ensure it is not publicly accessible and has strong credentials."),
        6379: ("Critical", "Redis service detected. Redis is often unauthenticated by default; ensure it is secured."),
        27017: ("Critical", "MongoDB service detected. Ensure authentication is enabled and access is restricted."),
        3389: ("High", "RDP service detected. Ensure it uses NLA and is not publicly accessible."),
        5900: ("High", "VNC service detected. Ensure it is encrypted and requires strong authentication."),
        4444: ("Critical", "Metasploit/Shell service detected. High indication of compromise or open backdoor.")
    }

    async def run(self, progress: Progress) -> List[Dict[str, Any]]:
        intensity = self.options.get("intensity", "normal")
        ports = self.options.get("ports", "1-1024")
        
        nmap_args = self._get_nmap_args(intensity, ports)
        
        task = progress.add_task(f"[green]Running Nmap ({intensity}) on {self.target}...", total=100)
        
        try:
            cmd = f"nmap -oX - {nmap_args} {self.target}"
            logger.debug(f"Executing: {cmd}")
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Since we can't easily track Nmap progress in XML mode, we simulate or wait
            # Real Nmap progress could be parsed from stderr with --stats-every
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Nmap failed: {stderr.decode()}")
                return []

            progress.update(task, completed=80, description="[cyan]Parsing Nmap XML output...")
            findings = self._parse_nmap_xml(stdout.decode())
            
            # 2. CVE Lookup for identified products/versions
            if intensity != "light":
                progress.update(task, completed=90, description="[cyan]Performing CVE lookups for services...")
                for finding in findings:
                    extra = finding.get("extra", {})
                    product = extra.get("product")
                    version = extra.get("version")
                    if product and version and product != "unknown":
                        cves = await self._lookup_cves(product, version)
                        if cves:
                            extra["cves"] = cves
                            finding["detail"] += f" | Known CVEs: {', '.join(cves)}"
                            # Upgrade severity if critical CVEs found (simple logic)
                            if finding["severity"] not in ["Critical", "High"]:
                                finding["severity"] = "High"

            progress.update(task, completed=100)
            return findings

        except Exception as e:
            logger.error(f"Network scan error: {e}")
            return []

    def _get_nmap_args(self, intensity: str, ports: str) -> str:
        profiles = {
            "light": f"-T2 -F -p {ports} --open",
            "normal": f"-T3 -sV -O -p {ports} --open --osscan-limit",
            "aggressive": f"-T4 -sV -sC -O -A -p {ports} --open"
        }
        return profiles.get(intensity, profiles["normal"])

    def _parse_nmap_xml(self, xml_data: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            root = ET.fromstring(xml_data)
            host = root.find("host")
            if host is None: return []

            # Host Info
            ip = host.find("address").get("addr")
            os_match = host.find(".//osmatch")
            os_name = os_match.get("name") if os_match is not None else "Unknown"

            for port_elem in host.findall(".//port"):
                port_id = int(port_elem.get("portid"))
                protocol = port_elem.get("protocol")
                state = port_elem.find("state").get("state")
                
                service_elem = port_elem.find("service")
                service_name = service_elem.get("name") if service_elem is not None else "unknown"
                product = service_elem.get("product", "unknown") if service_elem is not None else "unknown"
                version = service_elem.get("version", "unknown") if service_elem is not None else "unknown"

                if state == "open":
                    # Check if port is in our risky list
                    if port_id in self.RISKY_PORTS:
                        severity, rec = self.RISKY_PORTS[port_id]
                        findings.append(build_finding(
                            self.target, "risky_port_exposed",
                            f"Port {port_id} ({service_name}) is open. Product: {product} {version}",
                            severity, rec, "network",
                            extra={
                                "port": port_id, "protocol": protocol, 
                                "service": service_name, "product": product, 
                                "version": version, "os": os_name
                            }
                        ))
                    else:
                        # General Info for other open ports
                        findings.append(build_finding(
                            self.target, "open_port",
                            f"Port {port_id} ({service_name}) is open.",
                            "Info", "Review if this port needs to be exposed.",
                            "network",
                            extra={"port": port_id, "service": service_name}
                        ))
        except Exception as e:
            logger.error(f"XML Parsing error: {e}")
        return findings

    async def _lookup_cves(self, product: str, version: str) -> List[str]:
        if product == "unknown" or version == "unknown":
            return []
            
        query = f"{product} {version}"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
        
        cve_list = []
        try:
            async with self.get_session() as session:
                async with session.get(url, timeout=10, **self.get_request_params()) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        for v in vulnerabilities[:5]: 
                            cve_id = v.get("cve", {}).get("id")
                            if cve_id:
                                cve_list.append(cve_id)
        except Exception as e:
            logger.error(f"CVE Lookup failed: {e}")
            
        return cve_list

    def render_results(self, results: List[Dict[str, Any]]):
        if not results:
            self.console.print("[yellow]No open ports found or scan failed.[/yellow]")
            return

        table = Table(title=f"Network Scan Results for {self.target}")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="magenta")
        table.add_column("Product", style="green")
        table.add_column("Severity", style="bold")

        for r in results:
            extra = r.get("extra", {})
            port = extra.get("port", "N/A")
            service = extra.get("service", "unknown")
            product = extra.get("product", "unknown")
            sev = r['severity']
            
            color = "red" if sev == "Critical" else "orange3" if sev == "High" else "yellow" if sev == "Medium" else "cyan" if sev == "Low" else "dim white"
            
            table.add_row(str(port), service, product, f"[{color}]{sev}[/{color}]")

        self.console.print(table)
