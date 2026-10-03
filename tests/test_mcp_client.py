import asyncio
import json
import sys

import pytest

pytest.importorskip("mcp")

from spaf.mcp.client import MCPClientManager, load_config  # noqa: E402


def test_load_config_claude_desktop_shape(tmp_path):
    p = tmp_path / "mcp_servers.json"
    p.write_text(json.dumps({"mcpServers": {
        "cve": {"command": "echo", "args": ["x"]},
        "bad": {"args": ["no-command"]},   # dropped: no command
    }}))
    cfg = load_config(str(p))
    assert "cve" in cfg and "bad" not in cfg


def test_load_config_missing_file_is_empty(tmp_path):
    assert load_config(str(tmp_path / "nope.json")) == {}


def test_unknown_server_raises():
    mgr = MCPClientManager(config={})

    async def main():
        with pytest.raises(KeyError):
            await mgr.list_tools("nope")

    asyncio.run(main())


def test_roundtrip_against_spaf_own_server(tmp_path):
    """Integration: connect the client to SPAF's own MCP server as a subprocess."""
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": ["example.com"], "out_of_scope": []}))
    code = (
        "from spaf.mcp.server import run; run(scope_file=%r)" % str(scope)
    )
    mgr = MCPClientManager(config={
        "self": {"command": sys.executable, "args": ["-c", code]}
    })

    async def main():
        tools = await asyncio.wait_for(mgr.list_tools("self"), timeout=30)
        names = {t["name"] for t in tools}
        assert {"recon", "scope_show", "agent_run"} <= names
        # call a safe read-only tool
        res = await asyncio.wait_for(
            mgr.call_tool("self", "scope_show", {}), timeout=30)
        assert "example.com" in str(res)

    asyncio.run(main())
