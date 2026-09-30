import json

from spaf.reports.generator import ReportGenerator

FINDINGS = [
    {
        "vuln_type": "server_version_disclosure",
        "detail": "Server header: <script>alert(1)</script> nginx/1.0",
        "severity": "Low", "severity_order": 4,
        "recommendation": "Hide the <Server> header",
        "scan_type": "webscan", "discovered_at": "2026-01-01",
    },
    {
        "vuln_type": "nuclei:cve-2021-1", "detail": "boom",
        "severity": "Critical", "severity_order": 1,
        "recommendation": "patch", "scan_type": "toolkit",
        "discovered_at": "2026-01-01",
    },
]


def _gen(ai=None):
    return ReportGenerator("example.com", FINDINGS, {"target": "example.com"}, ai_analysis=ai)


def test_html_escapes_attacker_controlled_fields(tmp_path):
    p = tmp_path / "r.html"
    _gen().generate_html(str(p))
    out = p.read_text()
    # Raw script tag from a finding detail must never appear unescaped.
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_html_has_chart_and_module_breakdown(tmp_path):
    p = tmp_path / "r.html"
    _gen().generate_html(str(p))
    out = p.read_text()
    assert "Severity Distribution" in out
    assert "Findings by Module" in out
    assert "bar-fill" in out


def test_html_ai_section_only_when_provided(tmp_path):
    p1 = tmp_path / "no_ai.html"
    _gen().generate_html(str(p1))
    assert "AI Threat Intelligence" not in p1.read_text()

    p2 = tmp_path / "ai.html"
    _gen(ai="## Summary\nThis is **critical**.\n\n- a\n- b").generate_html(str(p2))
    out = p2.read_text()
    assert "AI Threat Intelligence" in out
    assert "<strong>critical</strong>" in out
    assert "<li>a</li>" in out


def test_md_to_html_escapes_then_formats():
    g = _gen()
    rendered = g._md_to_html("<b>x</b> **bold** `code`")
    assert "&lt;b&gt;" in rendered            # raw HTML escaped
    assert "<strong>bold</strong>" in rendered  # markdown applied after escape
    assert "<code>code</code>" in rendered


def test_json_report_structure(tmp_path):
    p = tmp_path / "r.json"
    _gen(ai="notes").generate_json(str(p))
    data = json.loads(p.read_text())
    assert data["summary"]["Critical"] == 1
    assert data["summary"]["Total"] == 2
    assert data["by_module"]["toolkit"] == 1
    assert data["ai_analysis"] == "notes"
