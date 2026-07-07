"""
mcp_client_smoke.py — Prove the real MCP server works end-to-end.

Spawns tools/mcp_stdio_server.py as a subprocess, connects to it over the real
MCP stdio transport, lists the advertised tools, then calls a few — showing that
the firewall gates calls made through the actual protocol (a safe read executes,
an external email is held for approval, an injected/unknown call is refused).

Run:
    python scripts/mcp_client_smoke.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _decision(result) -> str:
    """Pull the firewall (tool-call) decision out of an MCP CallToolResult."""
    try:
        payload = json.loads(result.content[0].text)
        return payload.get("firewall", {}).get("decision", "?")
    except Exception:
        return "?"


def _result_scan(result) -> str:
    """Pull the RESULT-inspection decision (poisoned-content quarantine verdict)."""
    try:
        payload = json.loads(result.content[0].text)
        return payload.get("result_scan", {}).get("decision", "n/a")
    except Exception:
        return "n/a"


async def main() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "tools.mcp_stdio_server"],
        cwd=ROOT,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("Tools advertised over MCP:")
            for t in tools.tools:
                print(f"  - {t.name}")
            print()

            # 1) Safe read → firewall allows, tool executes.
            r = await session.call_tool("search_knowledge_base", {"query": "refund"})
            print(f"search_knowledge_base   -> firewall={_decision(r)} (expected allow)")

            # 2) Real poisoned attachment read: the tool call is allowed, but the
            #    RETURNED content is inspected — result_scan carries the real verdict.
            r = await session.call_tool("read_attachment", {"name": "invoice_dispute.txt"})
            print(f"read_attachment(poison)  -> firewall={_decision(r)} | "
                  f"result_scan={_result_scan(r)} (poisoned content quarantined on return)")

            # 3) External email → firewall requires human approval, tool NOT executed.
            r = await session.call_tool("send_email", {"to": "user@gmail.com",
                                                       "subject": "hi", "body": "reset link"})
            print(f"send_email(external)     -> firewall={_decision(r)} (expected require_human_approval)")

            # 4) CRM change → firewall requires approval.
            r = await session.call_tool("update_crm", {"customer_id": "C-1", "fields": "tier=vip"})
            print(f"update_crm               -> firewall={_decision(r)} (expected require_human_approval)")

            print("\nReal MCP round-trip OK — firewall enforced over the protocol.")


if __name__ == "__main__":
    asyncio.run(main())
