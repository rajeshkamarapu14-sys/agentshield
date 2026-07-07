"""
policy_engine.py — The deterministic decision brain.

Given a piece of content or a planned tool call, decide one of:
    allow | block | sanitize | require_human_approval | ask_clarification

The engine is split into three entry points, one per inspection stage:

    evaluate_text(text, source)          -> ticket / document / tool-response text
    evaluate_tool_call(call, user_input) -> a planned dry-run tool invocation
    evaluate_output(text)                -> the agent's final drafted reply

The firewall (firewall.py) runs the relevant stages and merges their verdicts
with `most_restrictive`, so the whole request fails closed: any single BLOCK wins.

Everything here is pure rules — no network, no LLM — which makes the eval results
100% reproducible. The optional LLM agents only *add* opinions on top.
"""

from __future__ import annotations

import re
from typing import List, Optional

from common import (
    Decision,
    FirewallDecision,
    RiskFinding,
    Severity,
    Source,
    ToolCall,
)
from guardrails.injection_rules import detect_injection, looks_like_injection, _RULES
from guardrails.sensitive_data import (
    classify_actions,
    detect_sensitive,
    detect_sensitive_disclosure_request,
    redact,
    redact_sensitive_data,
)

# Injection classes so dangerous that even benign-looking indirect content is
# blocked outright rather than sanitised — you cannot "clean" an exfiltration
# instruction and keep using the document safely.
_EXFIL_CLASSES = {"data_exfiltration", "credential_extraction", "system_prompt_leak",
                  "markdown_exfiltration", "false_authorization"}

# Content that is data, not instructions. Injection from these gets sanitised
# (strip the bad lines, keep the useful ones) unless it is exfil-class.
_INDIRECT_SOURCES = {
    Source.ATTACHMENT,
    Source.KNOWLEDGE_BASE,
    Source.EMAIL_THREAD,
    Source.TOOL_RESPONSE,
}


# --------------------------------------------------------------------------- #
# Tool policy table                                                           #
# --------------------------------------------------------------------------- #
# Classifies each dry-run tool by risk so the engine knows the baseline
# treatment before looking at arguments.
TOOL_RISK = {
    "search_knowledge_base": "read",
    "read_attachment": "read",
    "read_email_thread": "read",
    "lookup_customer_dry_run": "read",
    "list_tickets_dry_run": "read",
    "get_business_profile_dry_run": "read",
    "get_security_policy": "read",
    "draft_customer_reply": "draft",
    "create_ticket": "write_internal",
    "send_email_dry_run": "external_email",
    "update_crm_dry_run": "write_customer_record",
    "issue_refund_dry_run": "financial",
}

# CRM fields a support agent must never change via a tool call — editing these is
# a privilege-escalation / integrity risk regardless of who asks.
PROTECTED_CRM_FIELDS = {"balance", "is_admin", "admin", "role", "password",
                        "credit_limit", "permissions", "account_status"}

# Recipients on these domains are considered internal; anything else is external
# and therefore an email to them is a customer-/data-impacting action.
INTERNAL_DOMAINS = {"novacart.example", "acme-support.example", "acme.example",
                    "ourcompany.example"}

# Downstream-executable content that must never appear in a support reply
# (OWASP LLM05 — Improper Output Handling). Bounded, conservative patterns.
_UNSAFE_OUTPUT_RE = re.compile(
    r"<\s*script\b|</\s*script|javascript:|on(?:error|load|click)\s*="   # XSS
    r"|\bunion\s+select\b|;\s*(?:drop|delete|truncate|insert|update)\s+"  # SQLi
    r"|'\s*or\s*'1'\s*=\s*'1"                                             # SQLi
    r"|\brm\s+-rf\b|\$\([^)]+\)|`[^`]+`|;\s*(?:cat|curl|wget|bash|sh|nc)\s"  # shell
    r"|\.\./\.\./"                                                        # path traversal
    r"|\{\{[^}]{0,80}\}\}|\$\{[^}]{0,80}\}",                              # template injection
    re.I)


# --------------------------------------------------------------------------- #
# Stage 1 & 2: free-text inspection (ticket, attachment, KB doc, tool result) #
# --------------------------------------------------------------------------- #
def evaluate_text(text: str, source: Source, stage: str = "input") -> FirewallDecision:
    """Decide what to do with a block of untrusted text."""
    injection = detect_injection(text, source)
    sensitive = detect_sensitive(text, source)
    risks: List[RiskFinding] = injection + sensitive

    # Intent-based check: a direct user request to reveal/share/export sensitive
    # fields is blocked even when no actual value is present in the prompt.
    if source == Source.CUSTOMER_TICKET:
        disc = detect_sensitive_disclosure_request(text)
        if disc["sensitive_request_detected"]:
            drisks = [_finding(f"disclosure_request:{t}", Severity.HIGH, source,
                               f"request to disclose {t}")
                      for t in disc["requested_sensitive_types"]]
            return FirewallDecision(
                Decision.BLOCK,
                ["Request to disclose sensitive data blocked."] + disc["reason_codes"],
                risks=risks + drisks, stage=stage)

    if not risks:
        return FirewallDecision(Decision.ALLOW, ["No suspicious content detected."],
                                risks=[], stage=stage)

    has_exfil = any(f.risk_type in _EXFIL_CLASSES for f in injection)

    # Direct injection in the user's own message → block. A customer trying to
    # jailbreak the agent is never sanitised; we refuse the whole request.
    if injection and source == Source.CUSTOMER_TICKET:
        return FirewallDecision(
            Decision.BLOCK,
            ["Direct prompt injection detected in user input."]
            + [f"{f.risk_type}: {f.evidence}" for f in injection],
            risks=risks, stage=stage,
        )

    # Indirect injection (document / email / tool response).
    if injection and source in _INDIRECT_SOURCES:
        if has_exfil:
            return FirewallDecision(
                Decision.BLOCK,
                [f"Indirect injection with data/credential exfiltration via {source.value}."]
                + [f"{f.risk_type}: {f.evidence}" for f in injection],
                risks=risks, stage=stage,
            )
        # Benign document carrying an embedded instruction → strip and keep.
        cleaned = sanitize_text(text, source)
        return FirewallDecision(
            Decision.SANITIZE,
            [f"Suspicious instructions removed from {source.value}; benign content retained."]
            + [f"{f.risk_type}: {f.evidence}" for f in injection],
            risks=risks, stage=stage, sanitized_text=cleaned,
        )

    # Injection from some other source with no exfil, or sensitive-data-only text.
    if injection:
        return FirewallDecision(
            Decision.BLOCK,
            ["Prompt injection detected."]
            + [f"{f.risk_type}: {f.evidence}" for f in injection],
            risks=risks, stage=stage,
        )

    # Only sensitive data present → redact and continue.
    cleaned, labels = redact(text)
    return FirewallDecision(
        Decision.SANITIZE,
        [f"Sensitive data redacted: {', '.join(labels)}."],
        risks=risks, stage=stage, sanitized_text=cleaned,
    )


# --------------------------------------------------------------------------- #
# Stage 3: planned tool-call inspection                                       #
# --------------------------------------------------------------------------- #
def evaluate_tool_call(
    call: Optional[ToolCall],
    user_input: str = "",
    stage: str = "tool_call",
) -> FirewallDecision:
    """Decide whether a planned dry-run tool call may proceed."""
    if call is None or not call.name:
        return FirewallDecision(Decision.ALLOW, ["No tool call requested."], stage=stage)

    risk_class = TOOL_RISK.get(call.name)

    # Unknown / unregistered tool → block. The agent may only use the sanctioned
    # dry-run tool set; anything else is treated as an attempted escape.
    if risk_class is None:
        return FirewallDecision(
            Decision.BLOCK,
            [f"Tool '{call.name}' is not in the approved tool registry."],
            risks=[_finding("unauthorized_tool", Severity.HIGH, Source.TOOL_CALL,
                            f"unknown tool '{call.name}'")],
            stage=stage,
        )

    # Low-risk read/draft/internal-write tools are always allowed (dry-run).
    if risk_class in ("read", "draft", "write_internal"):
        return FirewallDecision(
            Decision.ALLOW, [f"Low-risk tool '{call.name}' permitted (dry-run)."], stage=stage
        )

    # --- External email ---
    if risk_class == "external_email":
        return _evaluate_email(call, stage)

    # --- CRM / customer-record write ---
    if risk_class == "write_customer_record":
        return _evaluate_crm(call, stage)

    # --- Financial (refund) ---
    if risk_class == "financial":
        return _evaluate_refund(call, stage)

    # Fail closed: any future/unhandled risk class is refused, not allowed.
    return FirewallDecision(
        Decision.BLOCK,
        [f"Unhandled tool risk class '{risk_class}' — blocked (fail-closed)."],
        risks=[_finding("unhandled_risk_class", Severity.HIGH, Source.TOOL_CALL, risk_class)],
        stage=stage)


def _evaluate_refund(call: ToolCall, stage: str) -> FirewallDecision:
    """Validate the refund *amount* against business thresholds (arg validation).

    <= auto-approve cap → allow · <= block ceiling → require approval ·
    above ceiling or unparseable → block.
    """
    from config import CONFIG
    raw = call.args.get("amount", 0)
    try:
        amount = float(str(raw).replace("$", "").replace(",", "").strip())
    except (TypeError, ValueError):
        return FirewallDecision(
            Decision.BLOCK, [f"Refund amount '{raw}' is not a valid number."],
            risks=[_finding("invalid_amount", Severity.MEDIUM, Source.TOOL_CALL, str(raw))],
            stage=stage)

    if amount < 0:
        return FirewallDecision(
            Decision.BLOCK, [f"Negative refund amount ({amount}) blocked."],
            risks=[_finding("invalid_amount", Severity.HIGH, Source.TOOL_CALL, str(amount))],
            stage=stage)
    if amount > CONFIG.refund_block_ceiling:
        return FirewallDecision(
            Decision.BLOCK,
            [f"Refund of ${amount:,.2f} exceeds the ${CONFIG.refund_block_ceiling:,.0f} "
             f"ceiling — blocked as likely abuse."],
            risks=[_finding("excessive_refund", Severity.HIGH, Source.TOOL_CALL, str(amount))],
            stage=stage)
    if amount <= CONFIG.refund_auto_approve_cap:
        return FirewallDecision(
            Decision.ALLOW,
            [f"Refund of ${amount:,.2f} is within the ${CONFIG.refund_auto_approve_cap:,.0f} "
             f"auto-approve limit."],
            stage=stage)
    return FirewallDecision(
        Decision.REQUIRE_HUMAN_APPROVAL,
        [f"Refund of ${amount:,.2f} exceeds the ${CONFIG.refund_auto_approve_cap:,.0f} "
         f"auto-approve limit — human approval required."],
        risks=[_finding("refund_over_cap", Severity.MEDIUM, Source.TOOL_CALL, str(amount))],
        stage=stage)


def _evaluate_email(call: ToolCall, stage: str) -> FirewallDecision:
    to = str(call.args.get("to", "")).strip()
    # Scan the payload only — exclude the recipient field itself, otherwise the
    # 'to' address would be mis-read as leaked PII and block every external send.
    body = " ".join(str(v) for k, v in call.args.items() if k != "to")

    # Recipient missing / placeholder → we don't know who this is going to.
    if not to or to in ("?", "unknown", "TBD") or _is_placeholder(to):
        return FirewallDecision(
            Decision.ASK_CLARIFICATION,
            ["Email recipient is missing or unclear — cannot send without a confirmed address."],
            stage=stage,
        )

    external = not _is_internal(to)
    # "Serious" sensitive data = anything the disclosure policy would redact or
    # block (DOB, phone, address, national IDs, cards, secrets). A masked-only
    # email address or a username in the body does not, by itself, trigger a block.
    action, sens_types = classify_actions(body)
    serious = action in ("redact", "block")
    inj = detect_injection(body, Source.TOOL_CALL)

    # External recipient + serious sensitive data / bulk / injection → block
    # (external sharing of sensitive data is not allowed).
    if external and (serious or _mentions_bulk(body) or inj):
        return FirewallDecision(
            Decision.BLOCK,
            [f"Blocked email to external recipient '{to}' carrying sensitive data "
             f"({', '.join(sens_types) or 'bulk/injected content'}) — external "
             f"disclosure not allowed."],
            risks=[_finding("external_sensitive_data", Severity.HIGH, Source.TOOL_CALL,
                            f"external send to {to}")],
            stage=stage,
        )

    # Any external email is customer-impacting → human must approve.
    if external:
        return FirewallDecision(
            Decision.REQUIRE_HUMAN_APPROVAL,
            [f"External email to '{to}' requires human approval before sending."],
            risks=[_finding("external_communication", Severity.MEDIUM, Source.TOOL_CALL,
                            f"external recipient {to}")],
            stage=stage,
        )

    # Internal recipient but the email carries sensitive data → high-risk internal
    # use → require human approval.
    if serious:
        return FirewallDecision(
            Decision.REQUIRE_HUMAN_APPROVAL,
            [f"Internal email to '{to}' carries sensitive data "
             f"({', '.join(sens_types)}) — human approval required."],
            risks=[_finding("internal_sensitive_use", Severity.MEDIUM, Source.TOOL_CALL,
                            ", ".join(sens_types))],
            stage=stage,
        )

    return FirewallDecision(
        Decision.ALLOW, [f"Internal email to '{to}' permitted (dry-run)."], stage=stage
    )


def _evaluate_crm(call: ToolCall, stage: str) -> FirewallDecision:
    target = str(call.args.get("customer_id", call.args.get("record_id", ""))).strip()
    body = " ".join(str(v) for v in call.args.values())

    # Arg validation: refuse edits to protected fields (privilege-escalation /
    # integrity risk), regardless of target or approval.
    touched = _crm_field_names(call.args)
    protected_hits = touched & PROTECTED_CRM_FIELDS
    if protected_hits:
        return FirewallDecision(
            Decision.BLOCK,
            [f"CRM update touches protected field(s): {', '.join(sorted(protected_hits))}."],
            risks=[_finding("protected_field_write", Severity.HIGH, Source.TOOL_CALL,
                            ", ".join(sorted(protected_hits)))],
            stage=stage)

    # No target record → ambiguous, ask which customer.
    if not target or _is_placeholder(target):
        return FirewallDecision(
            Decision.ASK_CLARIFICATION,
            ["CRM update has no clear target record — which customer/record should be changed?"],
            stage=stage,
        )

    # Bulk update → high blast radius. Require approval (or block if it looks like
    # an attempt to wipe/reset everything).
    if _mentions_bulk(body):
        if re.search(r"\b(delete|wipe|reset|purge|remove\s+all)\b", body, re.I):
            return FirewallDecision(
                Decision.BLOCK,
                ["Bulk destructive CRM operation blocked."],
                risks=[_finding("bulk_destructive", Severity.HIGH, Source.TOOL_CALL, body[:80])],
                stage=stage,
            )
        return FirewallDecision(
            Decision.REQUIRE_HUMAN_APPROVAL,
            ["Bulk CRM update requires human approval."],
            risks=[_finding("bulk_update", Severity.MEDIUM, Source.TOOL_CALL, body[:80])],
            stage=stage,
        )

    # Single-record change still modifies a customer record → require approval.
    return FirewallDecision(
        Decision.REQUIRE_HUMAN_APPROVAL,
        [f"CRM change to record '{target}' requires human approval (customer-record impact)."],
        risks=[_finding("customer_record_change", Severity.MEDIUM, Source.TOOL_CALL, target)],
        stage=stage,
    )


# --------------------------------------------------------------------------- #
# Stage 4: final-output inspection                                            #
# --------------------------------------------------------------------------- #
def evaluate_output(text: str, stage: str = "output") -> FirewallDecision:
    """Last line of defence before any reply is shown.

    Per the disclosure policy, the reply is ALWAYS run through
    redact_sensitive_data() first: secrets/cards → [REDACTED_SECRET]/[REDACTED_CARD],
    PII → labels, emails → masked. The (redacted) reply then proceeds — "safe
    summaries may proceed with redacted values". A reply that echoes an injected
    instruction is blocked outright.
    """
    if not text or not text.strip():
        return FirewallDecision(Decision.ALLOW, ["Empty output."], stage=stage)

    # A reply that parrots an injection is refused, not just redacted.
    injection_echo = detect_injection(text, Source.OUTPUT)
    if injection_echo:
        return FirewallDecision(
            Decision.BLOCK,
            ["Final reply echoes injected instructions — blocked."],
            risks=injection_echo, stage=stage,
        )

    # Improper-output-handling guard (OWASP LLM05): a support reply should never
    # contain downstream-executable content (script/SQL/shell/path-traversal/
    # template). If it does, block it before it reaches any browser/DB/executor.
    if _UNSAFE_OUTPUT_RE.search(text):
        return FirewallDecision(
            Decision.BLOCK,
            ["Reply contains downstream-executable content "
             "(script/SQL/shell/traversal/template) — blocked (improper output handling)."],
            risks=[_finding("unsafe_output_content", Severity.HIGH, Source.OUTPUT,
                            "code-injection-shaped output")],
            stage=stage,
        )

    cleaned, types = redact_sensitive_data(text)
    if types:
        risks = detect_sensitive(text, Source.OUTPUT)
        return FirewallDecision(
            Decision.SANITIZE,
            [f"Sensitive data redacted/masked in reply: {', '.join(types)}."],
            risks=risks, stage=stage, sanitized_text=cleaned,
        )

    return FirewallDecision(Decision.ALLOW, ["Output clean."], stage=stage)


# --------------------------------------------------------------------------- #
# Sanitisation helper                                                          #
# --------------------------------------------------------------------------- #
def sanitize_text(text: str, source: Source) -> str:
    """Remove any line that carries an injection, then redact sensitive data.

    Uses the SAME detection pipeline as the decision step (looks_like_injection,
    which normalizes/flattens and decodes base64/hex/ROT13) so that an obfuscated
    line that *triggered* a SANITIZE decision is actually stripped here — not just
    lines matching the raw rule patterns. Line-granularity keeps it explainable:
    we drop the poisoned sentence and keep surrounding legitimate content.
    """
    kept: List[str] = []
    for line in text.splitlines():
        # Match detection: also flatten the single line so a same-line sentence
        # split ("keep this. ignore all previous instructions.") is caught.
        if looks_like_injection(line, source):
            continue  # drop injected instruction line (raw or obfuscated)
        kept.append(line)
    cleaned = "\n".join(kept).strip()
    cleaned, _labels = redact(cleaned)
    return cleaned or "[content removed: entire document was flagged]"


# --------------------------------------------------------------------------- #
# Small internal helpers                                                       #
# --------------------------------------------------------------------------- #
def _finding(risk_type: str, sev: Severity, source: Source, evidence: str) -> RiskFinding:
    return RiskFinding(risk_type=risk_type, severity=sev, source=source, evidence=evidence)


def _is_internal(email: str) -> bool:
    domain = email.split("@")[-1].lower() if "@" in email else ""
    return domain in INTERNAL_DOMAINS


def _is_placeholder(value: str) -> bool:
    return bool(re.fullmatch(r"[<\[{（(]?\s*(x+|placeholder|tbd|na|n/a|todo|\.\.\.|\?+)"
                             r"\s*[>\]}）)]?", value.strip(), re.I))


def _crm_field_names(args: dict) -> set:
    """Collect the set of field names a CRM update would change.

    Handles both nested `fields={...}` and flat keyword args, lower-cased.
    """
    names = set()
    fields = args.get("fields")
    if isinstance(fields, dict):
        names |= {str(k).lower() for k in fields.keys()}
    elif isinstance(fields, str):
        # e.g. "is_admin=true" or "tier=vip" → take the left-hand side.
        names |= {p.split("=")[0].strip().lower() for p in fields.split(",") if "=" in p}
    for k in args:
        if k not in ("customer_id", "record_id", "fields"):
            names.add(str(k).lower())
    return names


def _mentions_bulk(text: str) -> bool:
    return bool(re.search(r"\b(all\s+(customers?|users?|records?|accounts?)"
                          r"|every\s+(customer|user|record)|entire\s+(database|list|table)"
                          r"|bulk|mass|\bthe\s+whole\s+(database|list))\b", text, re.I))
