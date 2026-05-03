import os
import json
from typing import Any, Dict, List
from datetime import datetime
from spaf.utils.logger import logger

class ReportGenerator:
    def __init__(self, target: str, scan_data: List[Dict[str, Any]], meta: Dict[str, Any]):
        self.target = target
        self.scan_data = scan_data
        self.meta = meta
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    def generate_json(self, output_path: str):
        """
        Generates a structured JSON report.
        """
        report = {
            "target": self.target,
            "generated_at": self.timestamp,
            "meta": self.meta,
            "findings": self.scan_data,
            "summary": self._get_counts()
        }
        try:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=4)
            logger.info(f"JSON report generated: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")

    def generate_html(self, output_path: str):
        """
        Generates a premium dark-themed HTML report.
        """
        counts = self._get_counts()
        findings_html = self._build_findings_html()
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SPAF Security Report - {self.target}</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --critical: #f85149;
            --high: #f0883e;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
            --recommendation-bg: #1f2937;
            --recommendation-border: #059669;
        }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 40px;
            line-height: 1.6;
        }}
        .header {{
            text-align: center;
            margin-bottom: 50px;
        }}
        .banner {{
            font-family: monospace;
            white-space: pre;
            color: #3fb950;
            font-size: 14px;
            margin-bottom: 20px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 50px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-value {{ font-size: 28px; font-weight: bold; margin-bottom: 5px; }}
        .stat-label {{ color: var(--text-muted); text-transform: uppercase; font-size: 12px; }}
        
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 30px;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 15px 25px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .finding-content {{ padding: 25px; }}
        .recommendation-box {{
            background: var(--recommendation-bg);
            border-left: 4px solid var(--recommendation-border);
            padding: 15px;
            margin-top: 20px;
            border-radius: 0 4px 4px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 60px;
            color: var(--text-muted);
            font-size: 12px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }}
        
        .c-Critical {{ color: var(--critical); }}
        .bg-Critical {{ background: var(--critical); color: white; }}
        .c-High {{ color: var(--high); }}
        .bg-High {{ background: var(--high); color: white; }}
        .c-Medium {{ color: var(--medium); }}
        .bg-Medium {{ background: var(--medium); color: white; }}
        .c-Low {{ color: var(--low); }}
        .bg-Low {{ background: var(--low); color: white; }}
        .c-Info {{ color: var(--info); }}
        .bg-Info {{ background: var(--info); color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="banner">
 ██████  ██████   █████  ███████ 
 ██       ██   ██ ██   ██ ██      
  ██████  ██████  ███████ █████   
       ██ ██      ██   ██ ██      
  ██████  ██      ██   ██ ██      
 SPAF SECURITY REPORT
        </div>
        <h1>Security Assessment for {self.target}</h1>
        <p style="color: var(--text-muted)">Generated on {self.timestamp} UTC</p>
    </div>

    <div class="summary-grid">
        <div class="stat-card"><div class="stat-value c-Critical">{counts['Critical']}</div><div class="stat-label">Critical</div></div>
        <div class="stat-card"><div class="stat-value c-High">{counts['High']}</div><div class="stat-label">High</div></div>
        <div class="stat-card"><div class="stat-value c-Medium">{counts['Medium']}</div><div class="stat-label">Medium</div></div>
        <div class="stat-card"><div class="stat-value c-Low">{counts['Low']}</div><div class="stat-label">Low</div></div>
        <div class="stat-card"><div class="stat-value">{counts['Total']}</div><div class="stat-label">Total Findings</div></div>
    </div>

    <div class="findings-list">
        {findings_html}
    </div>

    <div class="footer">
        <p>SMART PENTESTING AUTOMATION FRAMEWORK (SPAF)</p>
        <p style="font-weight: bold; color: var(--info);">Developed by gg(geevarghese)</p>
        <p>This report is for authorized security testing purposes only. Unauthorized use is prohibited.</p>
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

    def _get_counts(self) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "Total": 0}
        for f in self.scan_data:
            sev = f.get("severity", "Info")
            counts[sev] += 1
            counts["Total"] += 1
        return counts

    def _build_findings_html(self) -> str:
        html = ""
        # Sort by severity
        sorted_findings = sorted(self.scan_data, key=lambda x: x.get("severity_order", 99))
        
        for f in sorted_findings:
            sev = f.get("severity", "Info")
            html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <strong style="font-size: 18px;">{f.get('vuln_type').replace('_', ' ').title()}</strong>
                    <span class="severity-badge bg-{sev}">{sev}</span>
                </div>
                <div class="finding-content">
                    <p>{f.get('detail')}</p>
                    <div class="recommendation-box">
                        <strong>Recommendation:</strong><br>
                        {f.get('recommendation')}
                    </div>
                    <p style="font-size: 12px; color: var(--text-muted); margin-top: 15px;">
                        Discovered At: {f.get('discovered_at')} | Module: {f.get('scan_type')}
                    </p>
                </div>
            </div>
            """
        return html
