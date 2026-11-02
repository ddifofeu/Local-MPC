"""MCP transport: stdio only, so there is no listening socket and no network attack surface."""

from __future__ import annotations

import argparse
from typing import Optional

from .config import OrchestratorConfig
from .core import Orchestrator
from .secret import load_secret


def build_mcp(core: Orchestrator):
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("orchestrator", log_level="WARNING")

    @mcp.tool()
    async def route_task(task: str, override: Optional[str] = None, privacy: Optional[str] = None) -> dict:
        """Classify a task and return the routing decision (no execution). 'privacy' can only raise the level."""
        return await core.call("route_task", {"task": task, "override": override, "privacy": privacy})

    @mcp.tool()
    async def execute_task(task: Optional[str] = None, override: Optional[str] = None, privacy: Optional[str] = None,
                           input_file: Optional[str] = None, output_file: Optional[str] = None) -> dict:
        """Route and execute. For sensitive content prefer input_file/output_file (paths inside the workdir):
        the content then never transits through the calling model's context."""
        return await core.call("execute_task", {"task": task, "override": override, "privacy": privacy,
                                                "input_file": input_file, "output_file": output_file})

    @mcp.tool()
    async def get_routing_history(limit: int = 10) -> dict:
        """Recent routing decisions (metadata only, never task text)."""
        return await core.call("get_routing_history", {"limit": limit})

    @mcp.tool()
    async def check_resources() -> dict:
        """Health of local inference endpoints."""
        return await core.call("check_resources", {})

    return mcp


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m orchestrator", description="Orchestrator MCP server (stdio)")
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    config = OrchestratorConfig.load(args.config)
    core = Orchestrator(config, load_secret("anthropic_api_key"))
    build_mcp(core).run(transport="stdio")
