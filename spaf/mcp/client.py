"""
MCP client — let SPAF consume *external* MCP servers as additional capabilities.

Point SPAF at other MCP servers (CVE/OSINT feeds, your own tools) and it can list
and call their tools. Config is the same shape Claude Desktop uses:

    {
      "mcpServers": {
        "cve": { "command": "uvx", "args": ["some-cve-mcp"] }
      }
    }

Loaded from ``$SPAF_MCP_SERVERS`` or ``./mcp_servers.json``. A session is opened
per call (simple and robust); long-lived pooling can come later.

External MCP tools are made available to operators (CLI/API). They are **not**
auto-added to the autonomous agent's fixed action set — wiring an external tool
into the agent is an explicit, reviewed step.
"""

import json
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from spaf.utils.logger import logger

DEFAULT_CONFIG = os.getenv("SPAF_MCP_SERVERS", "mcp_servers.json")


def load_config(path: str = DEFAULT_CONFIG) -> Dict[str, Dict[str, Any]]:
    """Return {server_name: {command, args, env?}} from the config file."""
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
        servers = data.get("mcpServers", data) if isinstance(data, dict) else {}
        return {k: v for k, v in servers.items() if isinstance(v, dict) and v.get("command")}
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(f"mcp client: could not read {path}: {exc}")
        return {}


class MCPClientManager:
    def __init__(self, config: Optional[Dict[str, Dict[str, Any]]] = None,
                 config_path: str = DEFAULT_CONFIG):
        self.servers = config if config is not None else load_config(config_path)

    def names(self) -> List[str]:
        return list(self.servers)

    @asynccontextmanager
    async def _session(self, name: str):
        if name not in self.servers:
            raise KeyError(f"unknown MCP server '{name}'. Configured: {', '.join(self.servers) or 'none'}")
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client, StdioServerParameters
        spec = self.servers[name]
        params = StdioServerParameters(
            command=spec["command"],
            args=spec.get("args", []),
            env={**os.environ, **spec.get("env", {})},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session

    async def list_tools(self, name: str) -> List[Dict[str, Any]]:
        async with self._session(name) as session:
            res = await session.list_tools()
            return [{"name": t.name, "description": (t.description or "")} for t in res.tools]

    async def list_all_tools(self) -> Dict[str, List[Dict[str, Any]]]:
        out: Dict[str, List[Dict[str, Any]]] = {}
        for name in self.servers:
            try:
                out[name] = await self.list_tools(name)
            except Exception as exc:  # noqa: BLE001 - surface per-server, keep going
                logger.warning(f"mcp client: '{name}' failed: {exc}")
                out[name] = []
        return out

    async def call_tool(self, name: str, tool: str, arguments: Dict[str, Any]) -> Any:
        async with self._session(name) as session:
            return await session.call_tool(tool, arguments)
