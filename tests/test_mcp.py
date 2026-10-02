import asyncio
import json

import pytest

pytest.importorskip("mcp")  # skip if the mcp extra isn't installed

from spaf.mcp.server import build_server  # noqa: E402
from spaf.mcp import shaping  # noqa: E402
from spaf.service.models import ScanResult, Finding  # noqa: E402


def _server(tmp_path, scope=None):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(scope or {"in_scope": ["example.com"], "out_of_scope": []}))
    return build_server(str(p))


def test_server_registers_expected_tools(tmp_path):
    s = _server(tmp_path)
    names = asyncio.run(_tool_names(s))
    assert names >= {"recon", "toolkit", "scan", "webscan", "crawl",
                     "agent_run", "scope_show", "scope_add", "tools_status"}


async def _tool_names(s):
    return {t.name for t in await s.list_tools()}


def test_tool_schema_exposes_real_params(tmp_path):
    s = _server(tmp_path)

    async def main():
        tools = {t.name: t for t in await s.list_tools()}
        assert "url" in tools["webscan"].input_schema["properties"]
        assert "target" in tools["recon"].input_schema["properties"]
        agent = tools["agent_run"].input_schema["properties"]
        assert {"target", "goal", "dry_run", "aggressive"} <= set(agent)

    asyncio.run(main())


def test_active_tool_refuses_out_of_scope(tmp_path):
    s = _server(tmp_path)

    async def main():
        res = await s.call_tool("webscan", {"url": "https://evil.com"})
        assert "out_of_scope" in str(res)

    asyncio.run(main())


def test_agent_run_dry_run_returns_plan(tmp_path):
    s = _server(tmp_path)

    async def main():
        res = await s.call_tool("agent_run", {"target": "example.com", "dry_run": True})
        assert "plan" in str(res)

    asyncio.run(main())


def test_shaping_caps_findings():
    findings = [Finding(target="t", vuln_type=f"v{i}", severity="Info",
                        detail="x" * 500) for i in range(100)]
    r = ScanResult(module="toolkit", target="t", findings=findings,
                   counts={"Info": 100}, scan_id="abc")
    payload = shaping.scan_payload(r)
    assert payload["total_findings"] == 100
    assert payload["showing"] == shaping.MAX_FINDINGS
    assert len(payload["findings"][0]["detail"]) <= shaping.MAX_DETAIL + 1  # truncation marker
    assert "scan://abc" in payload["note"]
