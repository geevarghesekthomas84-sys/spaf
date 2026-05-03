import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Any, Dict, List, Set
from rich.table import Table
from rich.progress import Progress

from spaf.core.engine import BaseModule
from spaf.utils.risk import build_finding
from spaf.utils.logger import logger

class CrawlerModule(BaseModule):
    async def run(self, progress: Progress) -> List[Dict[str, Any]]:
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        max_depth = self.options.get("depth", 2)
        max_pages = self.options.get("max_pages", 50)
        
        visited = set()
        to_visit = [url]
        findings = []
        
        task = progress.add_task("[green]Crawling web application...", total=max_pages)
        
        async with self.get_session() as session:
            depth = 0
            while to_visit and depth < max_depth and len(visited) < max_pages:
                current_level = list(to_visit)
                to_visit = []
                for current_url in current_level:
                    if current_url in visited or len(visited) >= max_pages:
                        continue
                        
                    visited.add(current_url)
                    progress.update(task, advance=1, description=f"[cyan]Crawling: {current_url[:50]}...")
                    
                    try:
                        async with session.get(current_url, timeout=5, **self.get_request_params()) as resp:
                            if resp.status == 200:
                                html = await resp.text()
                                soup = BeautifulSoup(html, 'html.parser')
                                
                                # Extract links
                                for a in soup.find_all('a', href=True):
                                    link = urljoin(current_url, a['href'])
                                    parsed_link = urlparse(link)
                                    # Stay on same domain
                                    if parsed_link.netloc == urlparse(url).netloc:
                                        if link not in visited:
                                            to_visit.append(link)
                                            
                                # Check for interesting things (forms, inputs, sensitive keywords)
                                findings.extend(self._analyze_page(current_url, html, soup))
                                
                    except Exception:
                        pass
                depth += 1
                
        progress.update(task, completed=max_pages)
        
        if visited:
            findings.append(build_finding(
                self.target, "crawl_summary",
                f"Successfully crawled {len(visited)} pages.",
                "Info", "Review discovered pages for further testing.",
                "crawler", extra={"pages_crawled": len(visited)}
            ))
            
        return findings

    def _analyze_page(self, url: str, html: str, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        findings = []
        # Check for forms
        forms = soup.find_all('form')
        if forms:
            findings.append(build_finding(
                url, "form_detected",
                f"Detected {len(forms)} HTML forms.",
                "Info", "Audit forms for CSRF protection and injection vulnerabilities.",
                "crawler", extra={"forms_count": len(forms)}
            ))
            
        # Check for sensitive keywords in source
        keywords = ["password", "secret", "token", "apikey", "config", "backup"]
        for kw in keywords:
            if kw in html.lower():
                findings.append(build_finding(
                    url, "sensitive_keyword_in_source",
                    f"Sensitive keyword '{kw}' found in page source.",
                    "Low", "Verify if sensitive information is being leaked in the client-side code.",
                    "crawler"
                ))
        return findings

    def render_results(self, results: List[Dict[str, Any]]):
        if not results:
            self.console.print("[yellow]No interesting findings identified during crawl.[/yellow]")
            return

        table = Table(title="Web Crawler Findings")
        table.add_column("Location", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Severity", style="bold")

        for r in results:
            sev = r['severity']
            color = "red" if sev == "Critical" else "orange3" if sev == "High" else "yellow" if sev == "Medium" else "cyan"
            table.add_row(r['target'], r['vuln_type'], f"[{color}]{sev}[/{color}]")

        self.console.print(table)
