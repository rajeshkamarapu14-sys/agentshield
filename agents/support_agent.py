"""
SupportAgent — the tool-using agent AgentShield protects.

Given a customer ticket it (a) looks up relevant KB context, (b) plans a tool
call, and (c) drafts a reply. It is deterministic by default (keyword planner) so
the demo is reproducible; if Gemini is configured it can draft a nicer reply, but
that path is optional and never required.

Importantly, the SupportAgent is *untrusted* from the firewall's point of view —
it can be manipulated by injected content. That's the whole point: AgentShield
sits between this agent's intentions and any real effect.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from common import ToolCall
from tools.mcp_server import call_tool


@dataclass
class Plan:
    """What the support agent intends to do about a ticket."""

    tool_call: Optional[ToolCall]
    rationale: str
    kb_context: str = ""


class SupportAgent:
    name = "SupportAgent"

    def gather_context(self, ticket: str) -> str:
        """Pull KB text relevant to the ticket (firewall-gated read).

        The ticket is passed as user_input so the INPUT firewall runs too — a
        malicious ticket can't drive even a read tool.
        """
        resp = call_tool("search_knowledge_base", {"query": ticket}, user_input=ticket)
        result = resp.get("result") or {}
        return result.get("text", "")

    def plan(self, ticket: str) -> Plan:
        """Decide on a single tool call using simple, transparent keyword rules."""
        t = ticket.lower()
        kb = self.gather_context(ticket)

        if any(w in t for w in ("refund", "charge back", "money back")):
            return Plan(
                ToolCall("update_crm_dry_run",
                         {"customer_id": "C-1001", "fields": {"refund_requested": "true"}}),
                "Refund request → record on CRM (needs approval).", kb)
        if any(w in t for w in ("email", "send", "confirmation", "receipt")):
            return Plan(
                ToolCall("send_email_dry_run",
                         {"to": "customer@example.com", "subject": "Your request",
                          "body": "Follow-up on your ticket."}),
                "Customer asked to be emailed → external send (needs approval).", kb)
        if any(w in t for w in ("track", "order", "shipping", "delivery", "status")):
            return Plan(
                ToolCall("search_knowledge_base", {"query": "order tracking"}),
                "Order status question → KB lookup.", kb)
        # Default: create an internal ticket for a human to follow up.
        return Plan(
            ToolCall("create_ticket", {"title": ticket[:60], "body": ticket}),
            "General request → log an internal ticket.", kb)

    def draft_reply(self, ticket: str, notes: str = "") -> str:
        """Draft a customer reply (dry-run; inspected by the output guardrail)."""
        resp = call_tool("draft_customer_reply", {"ticket": ticket, "notes": notes},
                         user_input=ticket)
        return (resp.get("result") or {}).get("text", "")
