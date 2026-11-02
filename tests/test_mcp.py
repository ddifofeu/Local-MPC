"""End to end over the real MCP stdio protocol, in a subprocess (also checks I7: clean stdout)."""

import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent


async def test_stdio_server_lists_tools_and_fails_closed(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"audit_log_file": str(tmp_path / "audit.jsonl")}))
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "orchestrator", "--config", str(cfg)], cwd=str(ROOT),
        env={"PATH": os.environ["PATH"], "ORCH_SECRETS_DIR": "/nonexistent"})
    async with stdio_client(params) as (rd, wr):
        async with ClientSession(rd, wr) as sess:
            await sess.initialize()
            tools = sorted(t.name for t in (await sess.list_tools()).tools)
            res = await sess.call_tool("route_task", {"task": "mon mot de passe est Hunter2"})
            payload = res.structuredContent or json.loads(res.content[0].text)
    assert tools == ["check_resources", "execute_task", "get_routing_history", "route_task"]
    assert payload["code"] == "NO_ROUTE"
