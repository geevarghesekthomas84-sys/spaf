import asyncio
import json

from spaf.modules.toolkit import ToolkitModule, TOOL_REGISTRY


def _make(target="example.com", options=None):
    return ToolkitModule(target, options or {})


def test_registry_has_all_ten_tools():
    expected = {
        "subfinder", "assetfinder", "dnsx", "httpx", "katana",
        "hakrawler", "waybackurls", "gau", "ffuf", "nuclei",
    }
    assert set(TOOL_REGISTRY) == expected
    for meta in TOOL_REGISTRY.values():
        assert meta["role"] and meta["url"].startswith("https://")


def test_domain_parsing():
    assert _make("example.com")._domain() == "example.com"
    assert _make("https://api.example.com/x")._domain() == "api.example.com"
    assert _make("example.com/path")._domain() == "example.com"


def test_missing_tool_finding_shape():
    f = _make()._missing_tool_finding("example.com", "subfinder")
    assert f["vuln_type"] == "tool_not_installed"
    assert f["severity"] == "Info"
    assert f["extra"]["tool"] == "subfinder"
    assert "subfinder" in f["detail"]


def test_parse_ffuf(tmp_path):
    out = tmp_path / "ffuf.json"
    out.write_text(json.dumps({
        "results": [
            {"url": "https://example.com/admin", "status": 200, "length": 512},
            {"url": "https://example.com/backup", "status": 403, "length": 12},
        ]
    }))
    findings = _make()._parse_ffuf(str(out), "https://example.com")
    assert len(findings) == 2
    assert findings[0]["vuln_type"] == "content_discovered"
    assert findings[0]["extra"]["status"] == 200
    assert "/admin" in findings[0]["target"]


def test_parse_ffuf_missing_file_is_safe():
    assert _make()._parse_ffuf("/no/such/file.json", "https://example.com") == []


def test_probe_http_parses_json(monkeypatch):
    mod = _make()
    monkeypatch.setattr(mod, "_available", lambda tool: True)

    lines = [
        json.dumps({"url": "https://example.com", "status_code": 200,
                    "title": "Home", "tech": ["nginx"]}),
        json.dumps({"url": "https://api.example.com", "status_code": 401}),
        "not-json-should-be-ignored",
    ]

    async def fake_stdin(name, args, data, timeout=300):
        return lines

    monkeypatch.setattr(mod, "_run_tool_stdin", fake_stdin)

    live_urls, findings = asyncio.run(mod._probe_http("example.com", ["example.com"]))
    assert live_urls == ["https://example.com", "https://api.example.com"]
    assert all(f["vuln_type"] == "live_web_host" for f in findings)
    assert findings[0]["extra"]["tech"] == ["nginx"]


def test_probe_http_missing_tool(monkeypatch):
    mod = _make()
    monkeypatch.setattr(mod, "_available", lambda tool: False)
    live_urls, findings = asyncio.run(mod._probe_http("example.com", ["example.com"]))
    assert live_urls == []
    assert findings[0]["vuln_type"] == "tool_not_installed"


def test_nuclei_parses_jsonl_and_maps_severity(monkeypatch):
    mod = _make()
    monkeypatch.setattr(mod, "_available", lambda tool: True)

    lines = [
        json.dumps({
            "template-id": "cve-2021-1234",
            "matched-at": "https://example.com/x",
            "info": {"name": "Test CVE", "severity": "critical",
                     "description": "boom", "tags": ["cve"]},
        }),
        json.dumps({
            "template-id": "tech-detect",
            "host": "https://example.com",
            "info": {"name": "Nginx", "severity": "info"},
        }),
        "",
    ]

    async def fake_stdin(name, args, data, timeout=300):
        return lines

    monkeypatch.setattr(mod, "_run_tool_stdin", fake_stdin)
    findings = asyncio.run(mod._nuclei("example.com", ["https://example.com"]))
    assert len(findings) == 2
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["extra"]["template_id"] == "cve-2021-1234"
    assert findings[1]["severity"] == "Info"


def test_nuclei_missing_tool(monkeypatch):
    mod = _make()
    monkeypatch.setattr(mod, "_available", lambda tool: False)
    findings = asyncio.run(mod._nuclei("example.com", ["https://example.com"]))
    assert findings[0]["vuln_type"] == "tool_not_installed"


def test_exec_handles_missing_binary():
    # A binary that certainly does not exist should return [] gracefully.
    mod = _make()
    out = asyncio.run(mod._exec("nope", ["spaf_nonexistent_binary_xyz"], None, timeout=5))
    assert out == []
