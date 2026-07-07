"""
common.py — Shared data model for AgentShield.

Everything in the system speaks in terms of the small set of types defined here:
the five firewall Decisions, the sources an attack can enter from, a RiskFinding
produced by a guardrail, the FirewallDecision returned by the policy engine, and
the Case shape used by the eval harness.

Keeping these in one dependency-free module means guardrails, tools, agents, and
the eval runner all agree on the same vocabulary without importing each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


# Detector backstop: the most text any single detector will scan. The firewall's
# fail-closed size limits (config.max_*_chars) BLOCK over-limit input before it
# reaches a detector, so allowed content is always scanned in full; this constant
# is a final safety bound (set to the max total-context limit) so a direct
# detector call on pathological input can't run unbounded.
MAX_INSPECT_CHARS = 100_000


class Decision(str, Enum):
    """The five outcomes the firewall can return for any inspected item.

    Subclassing `str` makes these JSON-serialisable and directly comparable to
    the plain strings used in the eval dataset (e.g. "block" == Decision.BLOCK).
    """

    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    REQUIRE_HUMAN_APPROVAL = "require_human_approval"
    ASK_CLARIFICATION = "ask_clarification"


# Ordering used when several inspection stages disagree. The firewall returns the
# single most-restrictive decision seen across all stages. BLOCK is the strongest
# safety signal; ALLOW is the weakest (only wins if nothing else fired).
DECISION_SEVERITY: Dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.ASK_CLARIFICATION: 1,
    Decision.SANITIZE: 2,
    Decision.REQUIRE_HUMAN_APPROVAL: 3,
    Decision.BLOCK: 4,
}


class Source(str, Enum):
    """Where a piece of inspected content originated.

    The five injection-source requirements map onto CUSTOMER_TICKET, ATTACHMENT,
    KNOWLEDGE_BASE, EMAIL_THREAD, and TOOL_RESPONSE. TOOL_CALL and OUTPUT cover
    the planned-action and final-reply inspection stages.
    """

    CUSTOMER_TICKET = "customer_ticket"
    ATTACHMENT = "attachment"
    KNOWLEDGE_BASE = "knowledge_base"
    EMAIL_THREAD = "email_thread"
    TOOL_RESPONSE = "tool_response"
    TOOL_CALL = "tool_call"
    OUTPUT = "output"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class RiskFinding:
    """A single thing a guardrail flagged as suspicious.

    Findings are the evidence trail: every block/sanitize/approval decision is
    justified by one or more findings, which are what we write to the audit log.
    """

    risk_type: str            # e.g. "prompt_injection", "data_exfiltration"
    severity: Severity
    source: Source
    evidence: str             # the matched snippet or a short human explanation
    detector: str = "rules"   # which component produced it ("rules" | "llm" | ...)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["source"] = self.source.value
        return d


@dataclass
class FirewallDecision:
    """The verdict the policy engine returns for one inspection.

    `sanitized_text` is only populated when decision == SANITIZE and carries the
    cleaned content the agent is allowed to keep using.
    """

    decision: Decision
    reasons: List[str] = field(default_factory=list)
    risks: List[RiskFinding] = field(default_factory=list)
    stage: str = "input"                     # which pipeline stage produced this
    sanitized_text: Optional[str] = None
    confidence: float = 1.0                  # 1.0 for deterministic rule hits

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reasons": self.reasons,
            "risks": [r.to_dict() for r in self.risks],
            "stage": self.stage,
            "sanitized_text": self.sanitized_text,
            "confidence": self.confidence,
        }


def most_restrictive(decisions: List[FirewallDecision]) -> FirewallDecision:
    """Combine per-stage decisions into one, taking the strongest safety signal.

    This is the firewall's fail-closed merge rule: if ANY stage said BLOCK, the
    whole request is blocked, regardless of what the other stages allowed.
    """

    if not decisions:
        return FirewallDecision(decision=Decision.ALLOW, reasons=["no findings"])
    winner = max(decisions, key=lambda d: DECISION_SEVERITY[d.decision])
    # Merge reasons/risks from every stage that agreed on the winning decision so
    # the audit log shows the full picture, not just the first matching stage.
    merged_reasons: List[str] = []
    merged_risks: List[RiskFinding] = []
    for d in decisions:
        if d.decision == winner.decision:
            merged_reasons.extend(d.reasons)
            merged_risks.extend(d.risks)
    return FirewallDecision(
        decision=winner.decision,
        reasons=merged_reasons or winner.reasons,
        risks=merged_risks or winner.risks,
        stage=winner.stage,
        sanitized_text=winner.sanitized_text,
        confidence=min((d.confidence for d in decisions), default=1.0),
    )


@dataclass
class ToolCall:
    """A planned (dry-run) tool invocation the support agent wants to make."""

    name: str
    args: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "args": self.args}

    @staticmethod
    def from_obj(obj: Optional[Dict[str, Any]]) -> Optional["ToolCall"]:
        if not obj:
            return None
        return ToolCall(name=obj.get("name", ""), args=obj.get("args", {}) or {})


@dataclass
class Case:
    """One eval / demo scenario, mirroring evals/test_cases.json exactly."""

    case_id: str
    title: str
    source: str
    user_input: str
    optional_context: str = ""
    planned_tool_call: Optional[Dict[str, Any]] = None
    expected_decision: str = ""
    expected_risks: List[str] = field(default_factory=list)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Case":
        return Case(
            case_id=d["case_id"],
            title=d.get("title", ""),
            source=d.get("source", ""),
            user_input=d.get("user_input", ""),
            optional_context=d.get("optional_context", "") or "",
            planned_tool_call=d.get("planned_tool_call"),
            expected_decision=d.get("expected_decision", ""),
            expected_risks=d.get("expected_risks", []) or [],
        )
