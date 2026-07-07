"""
ToolPolicyAgent — enforces the tool-use policy on planned tool calls.

A thin agent wrapper over guardrails.policy_engine.evaluate_tool_call so the
multi-agent architecture has a named component responsible for the "is this tool
call allowed?" question (external email, CRM writes, bulk actions, unknown
tools). Deterministic and side-effect free.
"""

from __future__ import annotations

from typing import Optional

from common import FirewallDecision, ToolCall
from guardrails.policy_engine import evaluate_tool_call


class ToolPolicyAgent:
    name = "ToolPolicyAgent"

    def check(self, call: Optional[ToolCall], user_input: str = "") -> FirewallDecision:
        """Return the firewall verdict for a planned tool call."""
        return evaluate_tool_call(call, user_input=user_input, stage="tool_call")
