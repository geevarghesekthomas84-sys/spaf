import asyncio
import aiohttp
import ssl
from datetime import datetime
from typing import Any, Dict, List
from rich.table import Table
from rich.progress import Progress

from spaf.core.engine import BaseModule
from spaf.utils.risk import build_finding
from spaf.utils.logger import logger

class WebscanModule(BaseModule):
    # Security Header Config: {header_name: severity}
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "High",
        "Content-Security-Policy": "High",
        "X-Frame-Options": "Medium",
        "X-Content-Type-Options": "Medium",
        "Referrer-Policy": "Low",
        "Permissions-Policy": "Low",
        "X-XSS-Protection": "Low"
    }

    SENSITIVE_PATHS = {
        "/.env": ("Critical", "Environment file exposed. High risk of credential leak."),
        "/.git/HEAD": ("Critical", "Git directory exposed. Source code can be reconstructed."),
        "/phpinfo.php": ("High", "PHP Info disclosure. Exposes system configuration."),
        "/server-status": ("High", "Apache Server Status exposed. Information leak."),
        "/actuator/env": ("Critical", "Spring Boot Actuator Env exposed. Significant data leak."),
        "/actuator": ("High", "Spring Boot Actuator endpoints exposed."),
        "/.htaccess": ("High", "Apache configuration file exposed."),
        "/wp-login.php": ("Medium", "WordPress login page found. Potential for brute-force."),
        "/admin/": ("Medium", "Generic admin panel path found."),
        "/console": ("High", "Management console path found."),
        "/api/swagger.json": ("Low", "Swagger API documentation exposed."),
        "/swagger-ui.html": ("Low", "Swagger UI documentation exposed."),
        "/crossdomain.xml": ("Medium", "Flash crossdomain policy found."),
        "/robots.txt": ("Info", "Robots.txt found."),
        "/sitemap.xml": ("Info", "Sitemap found.")
    }

    async def run(self, progress: Progress) -> List[Dict[str, Any]]:
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        findings = []
        
        task = progress.add_task("[green]Performing web security scan...", total=100)

        async with self.get_session() as session:
            # 1. Base Scan (Headers, Cookies, Server Info)
            progress.update(task, description="[cyan]Analyzing base URL and headers...", completed=20)
            try:
                async with session.get(url, timeout=10) as resp:
                    findings.extend(self._check_headers(resp.headers))
                    findings.extend(self._check_cookies(resp.cookies))
                    findings.extend(self._check_server_info(resp.headers))
            except Exception as e:
                logger.error(f"Base web request failed: {e}")

            # 2. TLS Check
            progress.update(task, description="[cyan]Checking TLS configuration...", completed=40)
            findings.extend(await self._check_tls(url))

            if not self.options.get("headers_only", False):
                # 3. Sensitive Path Probes
                progress.update(task, description="[cyan]Probing for sensitive paths...", completed=60)
                path_findings = await self._probe_paths(session, url)
                findings.extend(path_findings)

        progress.update(task, completed=100)
        return findings

    def _check_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for header, severity in self.SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(build_finding(
                    self.target, "missing_security_header",
                    f"The security header '{header}' is missing.",
                    severity, f"Implement the '{header}' header to enhance web security.",
                    "webscan"
                ))
        return findings

    def _check_cookies(self, cookies: Any) -> List[Dict[str, Any]]:
        findings = []
        for name, cookie in cookies.items():
            if not cookie.get('secure'):
                findings.append(build_finding(
                    self.target, "cookie_missing_secure_flag",
                    f"Cookie '{name}' is missing the 'Secure' flag.",
                    "Medium", "Set the 'Secure' attribute on all sensitive cookies.",
                    "webscan"
                ))
            if not cookie.get('httponly'):
                findings.append(build_finding(
                    self.target, "cookie_missing_httponly_flag",
                    f"Cookie '{name}' is missing the 'HttpOnly' flag.",
                    "Medium", "Set the 'HttpOnly' attribute to prevent XSS-based cookie theft.",
                    "webscan"
                ))
        return findings

    def _check_server_info(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        server = headers.get("Server")
        if server:
            findings.append(build_finding(
                self.target, "server_version_disclosure",
                f"Server header discloses software version: {server}",
                "Low", "Disable or obfuscate the 'Server' header in production.",
                "webscan"
            ))
        
        powered_by = headers.get("X-Powered-By")
        if powered_by:
            findings.append(build_finding(
                self.target, "x_powered_by_disclosure",
                f"X-Powered-By header discloses technology stack: {powered_by}",
                "Low", "Remove the 'X-Powered-By' header.",
                "webscan"
            ))

        cors = headers.get("Access-Control-Allow-Origin")
        if cors == "*":
            findings.append(build_finding(
                self.target, "cors_wildcard_detected",
                "CORS policy allows all origins (*).",
                "Medium", "Restrict 'Access-Control-Allow-Origin' to specific trusted domains.",
                "webscan"
            ))
            
        return findings

    async def _check_tls(self, url: str) -> List[Dict[str, Any]]:
        findings = []
        hostname = url.split("//")[-1].split("/")[0].split(":")[0]
        
        # 1. Check for deprecated protocols
        # We test for TLS 1.0 and 1.1 explicitly
        deprecated_protocols = [
            (ssl.TLSVersion.TLSv1, "TLS 1.0", "High"),
            (ssl.TLSVersion.TLSv1_1, "TLS 1.1", "High")
        ]
        
        for version, name, severity in deprecated_protocols:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = version
            ctx.maximum_version = version
            try:
                # Using wait_for to ensure we don't hang on slow connections
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, 443, ssl=ctx, server_hostname=hostname),
                    timeout=3
                )
                writer.close()
                await writer.wait_closed()
                findings.append(build_finding(
                    self.target, "deprecated_tls_protocol",
                    f"Server supports deprecated protocol: {name}",
                    severity, f"Disable {name} and enforce TLS 1.2 or higher.",
                    "webscan"
                ))
            except Exception:
                # Connection failed, likely protocol not supported (good)
                pass

        # 2. Check certificate info using default context (highest negotiated)
        ctx = ssl.create_default_context()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, 443, ssl=ctx, server_hostname=hostname),
                timeout=3
            )
            ssl_obj = writer.get_extra_info('ssl_obj')
            if ssl_obj:
                cert = ssl_obj.getpeercert()
                if cert:
                    not_after_str = cert.get('notAfter')
                    if not_after_str:
                        # Format: 'May 10 23:59:59 2024 GMT'
                        not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                        days_to_expire = (not_after - datetime.utcnow()).days
                        if days_to_expire < 0:
                            findings.append(build_finding(
                                self.target, "tls_certificate_expired",
                                f"TLS certificate expired on {not_after_str}",
                                "Critical", "Renew the TLS certificate immediately.",
                                "webscan"
                            ))
                        elif days_to_expire < 30:
                            findings.append(build_finding(
                                self.target, "tls_certificate_expiring_soon",
                                f"TLS certificate expires in {days_to_expire} days ({not_after_str})",
                                "Medium", "Renew the TLS certificate before it expires.",
                                "webscan"
                            ))
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        return findings

    async def _probe_paths(self, session: aiohttp.ClientSession, base_url: str) -> List[Dict[str, Any]]:
        findings = []
        concurrency = self.options.get("concurrency", 5)
        delay = self.options.get("delay", 0.0)
        semaphore = asyncio.Semaphore(concurrency)
        
        async def check_path(path, severity, rec):
            async with semaphore:
                if delay > 0:
                    await asyncio.sleep(delay)
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    async with session.get(url, timeout=5, allow_redirects=False, **self.get_request_params()) as resp:
                        if resp.status in [200, 403, 301, 302]:
                            findings.append(build_finding(
                                self.target, "sensitive_path_exposure",
                                f"Sensitive path found: {path} (Status: {resp.status})",
                                severity, rec, "webscan", extra={"path": path, "status": resp.status}
                            ))
                except Exception:
                    pass

        tasks = [check_path(p, s, r) for p, (s, r) in self.SENSITIVE_PATHS.items()]
        await asyncio.gather(*tasks)
        return findings

    def render_results(self, results: List[Dict[str, Any]]):
        if not results:
            self.console.print("[yellow]No web security findings identified.[/yellow]")
            return

        table = Table(title="Web Security Scan Findings")
        table.add_column("Finding Type", style="cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Detail", style="white")

        for r in results:
            sev = r['severity']
            color = "red" if sev == "Critical" else "orange3" if sev == "High" else "yellow" if sev == "Medium" else "cyan" if sev == "Low" else "dim white"
            table.add_row(r['vuln_type'], f"[{color}]{sev}[/{color}]", r['detail'])

        self.console.print(table)
