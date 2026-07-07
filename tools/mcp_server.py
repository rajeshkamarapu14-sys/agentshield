"""
mcp_server.py — MCP-style tool registry and dispatcher.

This is the single gateway through which the support agent invokes any tool. It
mirrors the shape of an MCP (Model Context Protocol) server: every tool has a
name, a JSON-schema-like description of its inputs, a risk classification, and a
`call(name, args)` dispatcher — the same contract an MCP client would consume.

Crucially, `call_tool` is firewall-aware: before dispatching a risky tool it asks
the policy engine for a verdict, and it refuses to execute anything that isn't
ALLOW. This is where "no risky action runs before the firewall clears it" is
enforced in code, not just in prose.

We intentionally implement an MCP-*style* in-process layer rather than a network
server so the demo/eval run offline with zero external processes. The registry
(`TOOLS`) is structured so it could be exposed over real MCP transport later
(see docs/architecture.md).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from common import (
    Decision, FirewallDecision, RiskFinding, Severity, Source, ToolCall, most_restrictive)
from guardrails.policy_engine import (
    TOOL_RISK, evaluate_tool_call, evaluate_text, sanitize_text)
from guardrails.sensitive_data import redact_sensitive_data

from tools import (
    search_knowledge_base,
    read_attachment,
    read_email_thread,
    draft_customer_reply,
    send_email_dry_run,
    update_crm_dry_run,
    create_ticket,
    get_security_policy,
    issue_refund_dry_run,
    lookup_customer,
    list_tickets,
    get_business_profile,
)


class ToolSpec:
    """MCP-style descriptor for one tool."""

    def __init__(self, name: str, description: str, handler: Callable[..., Dict[str, Any]],
                 input_schema: Dict[str, Any]):
        self.name = name
        self.description = description
        self.handler = handler
        self.input_schema = input_schema
        self.risk = TOOL_RISK.get(name, "unknown")

    def to_manifest(self) -> Dict[str, Any]:
        """MCP-style tool manifest entry."""
        return {
            "name": self.name,
            "description": self.description,
            "risk": self.risk,
            "inputSchema": self.input_schema,
        }


def _schema(**props: str) -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {k: {"type": "string", "description": v} for k, v in props.items()},
    }


# The registry. Adding a tool here is all it takes to expose it to the agent.
TOOLS: Dict[str, ToolSpec] = {
    "search_knowledge_base": ToolSpec(
        "search_knowledge_base", "Search the support knowledge base (read-only).",
        search_knowledge_base.run, _schema(query="Search terms")),
    "read_attachment": ToolSpec(
        "read_attachment", "Read the text of a customer-uploaded attachment (read-only).",
        read_attachment.run, _schema(name="Attachment filename")),
    "read_email_thread": ToolSpec(
        "read_email_thread", "Read a prior email thread (read-only). Untrusted content.",
        read_email_thread.run, _schema(name="Email thread filename")),
    "lookup_customer_dry_run": ToolSpec(
        "lookup_customer_dry_run", "Look up a customer record (read-only). Returns a "
        "summary with sensitive fields auto-redacted; no full card is stored.",
        lookup_customer.run, _schema(customer_id="Customer id")),
    "list_tickets_dry_run": ToolSpec(
        "list_tickets_dry_run", "List a customer's support tickets (read-only).",
        list_tickets.run, _schema(customer_id="Customer id")),
    "draft_customer_reply": ToolSpec(
        "draft_customer_reply", "Draft a reply to the customer (no send).",
        draft_customer_reply.run, _schema(ticket="Ticket id", notes="Draft notes")),
    "send_email_dry_run": ToolSpec(
        "send_email_dry_run", "Simulate sending an email. RISKY: external comms.",
        send_email_dry_run.run, _schema(to="Recipient", subject="Subject", body="Body")),
    "update_crm_dry_run": ToolSpec(
        "update_crm_dry_run", "Simulate updating a CRM record. RISKY: customer data.",
        update_crm_dry_run.run, _schema(customer_id="Customer id", fields="Fields to change")),
    "issue_refund_dry_run": ToolSpec(
        "issue_refund_dry_run", "Simulate issuing a refund. RISKY: financial; amount-gated.",
        issue_refund_dry_run.run, _schema(customer_id="Customer id", amount="Refund amount",
                                          reason="Reason")),
    "create_ticket": ToolSpec(
        "create_ticket", "Create an internal support ticket (low-risk write).",
        create_ticket.run, _schema(title="Title", body="Body", priority="Priority")),
    "get_business_profile_dry_run": ToolSpec(
        "get_business_profile_dry_run", "Return the business profile (company, country, "
        "currency, refund policy/thresholds) — read-only.",
        get_business_profile.run, _schema()),
    "get_security_policy": ToolSpec(
        "get_security_policy", "Return the written security policy (read-only).",
        get_security_policy.run, _schema()),
}


def list_tools() -> List[Dict[str, Any]]:
    """Return the MCP-style manifest of all registered tools."""
    return [spec.to_manifest() for spec in TOOLS.values()]


def call_tool(
    name: str,
    args: Optional[Dict[str, Any]] = None,
    user_input: str = "",
) -> Dict[str, Any]:
    """Dispatch a tool call, firewall-gated. There is NO bypass switch — the
    firewall always runs and the tool executes only if the merged verdict is ALLOW.

    Enforcement (fail-closed, most-restrictive merge):
      1. INPUT   — if `user_input` is supplied, it is inspected as a customer
                   ticket, so a direct prompt injection can't drive a tool call.
      2. TOOL    — the planned call is checked against the tool policy.
      3. RESULT  — the returned payload is re-inspected and quarantined/redacted
                   (recursively, all fields) before it reaches the agent.
    """
    args = args or {}

    spec = TOOLS.get(name)
    if spec is None:
        return {
            "tool": name,
            "executed": False,
            "firewall": {"decision": Decision.BLOCK.value,
                         "reasons": [f"Unknown tool '{name}'."]},
        }

    # Preflight: merge the input firewall (if user context is available) with the
    # tool-call policy. The strictest decision wins.
    stages = []
    if user_input and user_input.strip():
        stages.append(evaluate_text(user_input, Source.CUSTOMER_TICKET, stage="input"))
    stages.append(evaluate_tool_call(ToolCall(name, args), user_input=user_input,
                                     stage="tool_call"))
    verdict = most_restrictive(stages)

    if verdict.decision != Decision.ALLOW:
        # The firewall did not clear this request → do NOT execute the tool.
        return {
            "tool": name,
            "executed": False,
            "firewall": verdict.to_dict(),
        }

    result = spec.handler(**args)

    # Inspect the tool's RETURNED payload — a tool/API response is untrusted
    # (injection source #5). A poisoned result is quarantined (block) or cleaned
    # (sanitize) recursively across ALL fields before it reaches the agent.
    result, result_scan = _inspect_result(result)

    response = {
        "tool": name,
        "executed": True,
        "firewall": verdict.to_dict(),
        "result": result,
    }
    if result_scan is not None:
        response["result_scan"] = _safe_scan_dict(result_scan)
    return response


def _safe_scan_dict(scan) -> Dict[str, Any]:
    """A minimal, agent-safe view of the result scan.

    On BLOCK we return only a generic reason — never the raw evidence snippets,
    so a poisoned instruction fragment can't ride back to the agent via the scan
    metadata. On SANITIZE the (category-level) reasons are redacted for safety.
    """
    if scan.decision == Decision.BLOCK:
        return {"decision": "block",
                "reasons": ["Tool response blocked by firewall "
                            "(prompt-injection / exfiltration detected)."]}
    return {"decision": scan.decision.value,
            "reasons": [redact_sensitive_data(r)[0] for r in scan.reasons[:3]]}


def _collect_strings(obj: Any) -> List[str]:
    """Recursively gather every string value from a nested dict/list."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out: List[str] = []
        for v in obj.values():
            out.extend(_collect_strings(v))
        return out
    if isinstance(obj, list):
        out = []
        for v in obj:
            out.extend(_collect_strings(v))
        return out
    return []


def _clean_deep(obj: Any) -> Any:
    """Return a copy with sanitize_text applied to every string value.

    sanitize_text both STRIPS injected instruction lines and redacts PII, so a
    non-exfil injected line (e.g. "ignore previous instructions...") in a tool
    result is removed on the way back — not merely PII-redacted.
    """
    if isinstance(obj, str):
        return sanitize_text(obj, Source.TOOL_RESPONSE)
    if isinstance(obj, dict):
        return {k: _clean_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_deep(v) for v in obj]
    return obj


def _inspect_result(result: Any):
    """Re-inspect a tool's returned payload (source=tool_response) across ALL
    fields — not just `text` — so raw structured data can't bypass the firewall.

    Returns (possibly-modified result, scan_decision | None):
      * BLOCK    → the ENTIRE payload is replaced with a quarantine object
                   (raw records/fields are dropped, not just `text`).
      * SANITIZE → every string field (nested included) is redacted/masked.
      * ALLOW    → passed through unchanged.
    """
    if not isinstance(result, dict):
        return result, None
    joined = "\n".join(_collect_strings(result))
    if not joined.strip():
        return result, None

    # Fail-closed: an over-large tool response is quarantined, not scanned/truncated.
    from config import CONFIG
    if len(joined) > CONFIG.max_tool_response_chars:
        scan = FirewallDecision(
            Decision.BLOCK,
            [f"tool response {len(joined)} chars exceeds limit "
             f"{CONFIG.max_tool_response_chars} (input_too_large)"],
            stage="tool_response",
            risks=[RiskFinding("input_too_large", Severity.HIGH, Source.TOOL_RESPONSE,
                               f"{len(joined)} chars"),
                   RiskFinding("resource_exhaustion_protection", Severity.HIGH,
                               Source.TOOL_RESPONSE, "oversize tool response")])
        return {"tool": result.get("tool"), "dry_run": result.get("dry_run", True),
                "text": "[quarantined: tool response too large]", "quarantined": True}, scan

    scan = evaluate_text(joined, Source.TOOL_RESPONSE, stage="tool_response")
    if scan.decision == Decision.BLOCK:
        quarantined = {
            "tool": result.get("tool"),
            "dry_run": result.get("dry_run", True),
            "text": "[quarantined: tool response blocked by firewall — contained a "
                    "prompt-injection / exfiltration attempt]",
            "quarantined": True,
        }
        return quarantined, scan
    if scan.decision == Decision.SANITIZE:
        cleaned = _clean_deep(result)
        cleaned["sanitized"] = True
        return cleaned, scan
    return result, scan
