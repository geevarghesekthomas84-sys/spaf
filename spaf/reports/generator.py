import html
import json
import re
from typing import Any, Dict, List, Optional
from datetime import datetime

from spaf.utils.logger import logger

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


class ReportGenerator:
    def __init__(
        self,
        target: str,
        scan_data: List[Dict[str, Any]],
        meta: Dict[str, Any],
        ai_analysis: Optional[str] = None,
    ):
        self.target = target
        self.scan_data = scan_data
        self.meta = meta
        self.ai_analysis = ai_analysis
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------
    def generate_json(self, output_path: str):
        report = {
            "target": self.target,
            "generated_at": self.timestamp,
            "meta": self.meta,
            "summary": self._get_counts(),
            "by_module": self._counts_by_module(),
            "ai_analysis": self.ai_analysis,
            "findings": self.scan_data,
        }
        try:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=4, default=str)
            logger.info(f"JSON report generated: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------
    def generate_html(self, output_path: str):
        counts = self._get_counts()
        findings_html = self._build_findings_html()
        chart_html = self._build_severity_chart(counts)
        modules_html = self._build_module_breakdown()
        ai_html = self._build_ai_section()

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SPAF Security Report - {html.escape(self.target)}</title>
    <style>
        :root {{
            --bg-color: #0d1117; --card-bg: #161b22; --border-color: #30363d;
            --text-main: #c9d1d9; --text-muted: #8b949e;
            --critical: #f85149; --high: #f0883e; --medium: #d29922;
            --low: #3fb950; --info: #58a6ff;
            --recommendation-bg: #1f2937; --recommendation-border: #059669;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            background-color: var(--bg-color); color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            margin: 0; padding: 40px; line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .banner {{ font-family: monospace; white-space: pre; color: #3fb950; font-size: 14px; margin-bottom: 20px; }}
        h1, h2 {{ font-weight: 700; }}
        .summary-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 16px; margin-bottom: 32px;
        }}
        .stat-card {{
            background: var(--card-bg); border: 1px solid var(--border-color);
            padding: 20px; border-radius: 8px; text-align: center;
        }}
        .stat-value {{ font-size: 28px; font-weight: bold; margin-bottom: 5px; }}
        .stat-label {{ color: var(--text-muted); text-transform: uppercase; font-size: 12px; }}
        .panel {{
            background: var(--card-bg); border: 1px solid var(--border-color);
            border-radius: 10px; padding: 24px; margin-bottom: 32px;
        }}
        .panel h2 {{ margin-top: 0; }}
        .bar-row {{ display: flex; align-items: center; gap: 12px; margin: 10px 0; }}
        .bar-label {{ width: 80px; font-size: 13px; text-transform: uppercase; }}
        .bar-track {{ flex: 1; background: #0d1117; border-radius: 6px; overflow: hidden; height: 22px; }}
        .bar-fill {{ height: 100%; border-radius: 6px; min-width: 2px; transition: width .3s; }}
        .bar-count {{ width: 40px; text-align: right; font-variant-numeric: tabular-nums; }}
        .module-tag {{
            display: inline-block; background: #21262d; border: 1px solid var(--border-color);
            border-radius: 16px; padding: 4px 12px; margin: 4px; font-size: 13px;
        }}
        .finding-card {{
            background: var(--card-bg); border: 1px solid var(--border-color);
            border-radius: 10px; margin-bottom: 20px; overflow: hidden;
        }}
        .finding-header {{
            padding: 14px 22px; border-bottom: 1px solid var(--border-color);
            display: flex; justify-content: space-between; align-items: center; gap: 12px;
        }}
        .finding-title {{ font-size: 17px; font-weight: 600; word-break: break-word; }}
        .severity-badge {{
            padding: 4px 12px; border-radius: 20px; font-size: 12px;
            font-weight: bold; text-transform: uppercase; white-space: nowrap;
        }}
        .finding-content {{ padding: 22px; }}
        .finding-content p {{ word-break: break-word; }}
        .recommendation-box {{
            background: var(--recommendation-bg); border-left: 4px solid var(--recommendation-border);
            padding: 14px; margin-top: 16px; border-radius: 0 4px 4px 0;
        }}
        .ai-section pre {{
            background: #0d1117; border: 1px solid var(--border-color);
            border-radius: 6px; padding: 14px; overflow-x: auto;
        }}
        .ai-section code {{ font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; }}
        .footer {{
            text-align: center; margin-top: 50px; color: var(--text-muted);
            font-size: 12px; border-top: 1px solid var(--border-color); padding-top: 20px;
        }}
        .c-Critical {{ color: var(--critical); }} .bg-Critical {{ background: var(--critical); color: white; }}
        .c-High {{ color: var(--high); }} .bg-High {{ background: var(--high); color: white; }}
        .c-Medium {{ color: var(--medium); }} .bg-Medium {{ background: var(--medium); color: white; }}
        .c-Low {{ color: var(--low); }} .bg-Low {{ background: var(--low); color: white; }}
        .c-Info {{ color: var(--info); }} .bg-Info {{ background: var(--info); color: white; }}
    </style>
</head>
<body>
  <div class="container">
    <div class="header">
        <div class="banner"> ██████  ██████   █████  ███████
 ██       ██   ██ ██   ██ ██
  ██████  ██████  ███████ █████
       ██ ██      ██   ██ ██
  ██████  ██      ██   ██ ██
 SPAF SECURITY REPORT</div>
        <h1>Security Assessment for {html.escape(self.target)}</h1>
        <p style="color: var(--text-muted)">Generated on {self.timestamp} UTC</p>
    </div>

    <div class="summary-grid">
        <div class="stat-card"><div class="stat-value c-Critical">{counts['Critical']}</div><div class="stat-label">Critical</div></div>
        <div class="stat-card"><div class="stat-value c-High">{counts['High']}</div><div class="stat-label">High</div></div>
        <div class="stat-card"><div class="stat-value c-Medium">{counts['Medium']}</div><div class="stat-label">Medium</div></div>
        <div class="stat-card"><div class="stat-value c-Low">{counts['Low']}</div><div class="stat-label">Low</div></div>
        <div class="stat-card"><div class="stat-value">{counts['Total']}</div><div class="stat-label">Total Findings</div></div>
    </div>

    <div class="panel">
        <h2>Severity Distribution</h2>
        {chart_html}
    </div>

    {modules_html}
    {ai_html}

    <h2>Findings</h2>
    <div class="findings-list">
        {findings_html}
    </div>

    <div class="footer">
        <p>SMART PENTESTING AUTOMATION FRAMEWORK (SPAF)</p>
        <p style="font-weight: bold; color: var(--info);">Developed by gg (geevarghese)</p>
        <p>This report is for authorized security testing purposes only. Unauthorized use is prohibited.</p>
    </div>
  </div>
</body>
</html>
"""
        try:
            with open(output_path, "w") as f:
                f.write(html_template)
            logger.info(f"HTML report generated: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------
    def _get_counts(self) -> Dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        counts["Total"] = 0
        for f in self.scan_data:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1
            counts["Total"] += 1
        return counts

    def _counts_by_module(self) -> Dict[str, int]:
        modules: Dict[str, int] = {}
        for f in self.scan_data:
            mod = f.get("scan_type", "unknown")
            modules[mod] = modules.get(mod, 0) + 1
        return dict(sorted(modules.items(), key=lambda kv: kv[1], reverse=True))

    def _build_severity_chart(self, counts: Dict[str, int]) -> str:
        total = max(counts.get("Total", 0), 1)
        rows = ""
        for sev in SEVERITY_ORDER:
            n = counts.get(sev, 0)
            pct = (n / total) * 100
            rows += (
                f'<div class="bar-row">'
                f'<span class="bar-label c-{sev}">{sev}</span>'
                f'<span class="bar-track"><span class="bar-fill bg-{sev}" style="width:{pct:.1f}%"></span></span>'
                f'<span class="bar-count">{n}</span>'
                f"</div>"
            )
        return rows

    def _build_module_breakdown(self) -> str:
        modules = self._counts_by_module()
        if not modules:
            return ""
        tags = "".join(
            f'<span class="module-tag">{html.escape(str(m))} · {n}</span>'
            for m, n in modules.items()
        )
        return f'<div class="panel"><h2>Findings by Module</h2>{tags}</div>'

    def _build_ai_section(self) -> str:
        if not self.ai_analysis:
            return ""
        return (
            '<div class="panel ai-section">'
            '<h2>🤖 AI Threat Intelligence</h2>'
            f"{self._md_to_html(self.ai_analysis)}"
            "</div>"
        )

    def _build_findings_html(self) -> str:
        if not self.scan_data:
            return '<p style="color: var(--text-muted)">No findings.</p>'
        out = ""
        sorted_findings = sorted(self.scan_data, key=lambda x: x.get("severity_order", 99))
        for f in sorted_findings:
            sev = f.get("severity", "Info")
            title = html.escape(str(f.get("vuln_type", "finding")).replace("_", " ").title())
            detail = html.escape(str(f.get("detail", "")))
            rec = html.escape(str(f.get("recommendation", "")))
            discovered = html.escape(str(f.get("discovered_at", "")))
            module = html.escape(str(f.get("scan_type", "")))
            out += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-title">{title}</span>
                    <span class="severity-badge bg-{sev}">{html.escape(sev)}</span>
                </div>
                <div class="finding-content">
                    <p>{detail}</p>
                    <div class="recommendation-box"><strong>Recommendation:</strong><br>{rec}</div>
                    <p style="font-size: 12px; color: var(--text-muted); margin-top: 15px;">
                        Discovered At: {discovered} | Module: {module}
                    </p>
                </div>
            </div>"""
        return out

    # ------------------------------------------------------------------
    # Minimal, safe markdown → HTML for the AI section.
    # Everything is HTML-escaped first, then a small set of formatting rules is
    # applied, so AI output can never inject markup into the report.
    # ------------------------------------------------------------------
    def _md_to_html(self, text: str) -> str:
        escaped = html.escape(text)

        # Fenced code blocks ```...```
        def _code_block(m: re.Match) -> str:
            return f"<pre><code>{m.group(1)}</code></pre>"

        escaped = re.sub(r"```[a-zA-Z0-9]*\n(.*?)```", _code_block, escaped, flags=re.DOTALL)

        lines = escaped.split("\n")
        html_lines: List[str] = []
        in_list = False
        for line in lines:
            if "<pre>" in line or "</code></pre>" in line or line.strip().startswith("<"):
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                html_lines.append(line)
                continue
            stripped = line.strip()
            heading = re.match(r"^(#{1,4})\s+(.*)$", stripped)
            bullet = re.match(r"^[-*]\s+(.*)$", stripped)
            if heading:
                if in_list:
                    html_lines.append("</ul>"); in_list = False
                level = min(len(heading.group(1)) + 1, 5)
                html_lines.append(f"<h{level}>{self._inline_md(heading.group(2))}</h{level}>")
            elif bullet:
                if not in_list:
                    html_lines.append("<ul>"); in_list = True
                html_lines.append(f"<li>{self._inline_md(bullet.group(1))}</li>")
            elif stripped == "":
                if in_list:
                    html_lines.append("</ul>"); in_list = False
                html_lines.append("")
            else:
                if in_list:
                    html_lines.append("</ul>"); in_list = False
                html_lines.append(f"<p>{self._inline_md(stripped)}</p>")
        if in_list:
            html_lines.append("</ul>")
        return "\n".join(html_lines)

    def _inline_md(self, text: str) -> str:
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
        return text
