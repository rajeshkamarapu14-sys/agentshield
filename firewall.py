"""
firewall.py — The AgentShield pipeline.

This is the object the demo, the eval runner, and the app all call. It runs a
request through the inspection stages, merges the per-stage verdicts into one
fail-closed decision, writes an audit record, and (optionally) lets the JudgeAgent
score the outcome.

Inspection stages
-----------------
  1. INPUT    — the customer's own message                     (source=customer_ticket)
  2. CONTEXT  — any retrieved doc / attachment / email / tool
                output supplied with the request               (source varies)
  3. TOOL     — the planned dry-run tool call                  (source=tool_call)
  4. OUTPUT   — (optional) a drafted reply to inspect          (source=output)

The final decision is the MOST RESTRICTIVE across all stages (see
common.most_restrictive): a single BLOCK anywhere blocks the whole request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from common import (
    Case,
    Decision,
    FirewallDecision,
    RiskFinding,
    Severity,
    Source,
    ToolCall,
    most_restrictive,
)
from config import CONFIG
from guardrails.policy_engine import (
    evaluate_output,
    evaluate_text,
    evaluate_tool_call,
)
from agents.injection_detector_agent import InjectionDetectorAgent
from audit import write_entry


# Map the eval dataset's `source` strings onto the Source enum.
_SOURCE_MAP = {
    "customer_ticket": Source.CUSTOMER_TICKET,
    "attachment": Source.ATTACHMENT,
    "knowledge_base": Source.KNOWLEDGE_BASE,
    "email_thread": Source.EMAIL_THREAD,
    "tool_response": Source.TOOL_RESPONSE,
    "tool_call": Source.TOOL_CALL,
}


@dataclass
class FirewallResult:
    """Full outcome of running one request through the firewall."""

    decision: Decision
    final: FirewallDecision
    stages: List[FirewallDecision] = field(default_factory=list)
    case_id: str = ""
    session_id: str = ""
    source: str = ""
    planned_tool: Optional[str] = None
    detected_risks: List[RiskFinding] = field(default_factory=list)

    @property
    def reasons(self) -> List[str]:
        return self.final.reasons

    def audit_dict(self, user_request_summary: str = "",
                   judge_score: Optional[int] = None,
                   judge_verdict: Optional[str] = None,
                   judge_reason: Optional[str] = None,
                   judge_mode: Optional[str] = None,
                   needs_review: Optional[bool] = None,
                   agent_name: str = "AgentShield") -> Dict[str, Any]:
        """Shape one audit-log record per the required schema.

        Adds machine-readable `reason_codes`, the `max_severity` seen, and the
        firewall's `confidence` so decisions are easy to explain and aggregate.
        The judge_* fields carry the JudgeAgent's independent soundness audit of
        this decision (populated by inspect()).
        """
        return {
            "case_id": self.case_id or self.session_id,
            "session_id": self.session_id,
            "user_request_summary": user_request_summary,
            "source": self.source,
            "detected_risks": [r.to_dict() for r in self.detected_risks],
            "planned_tool": self.planned_tool,
            "decision": self.decision.value,
            "reason": "; ".join(self.reasons[:4]),
            "reason_codes": self._reason_codes(),
            "reason_code": self._reason_code(),
            "sensitive_types_detected": self._sensitive_types(),
            "sensitive_request_detected": bool(self._requested_sensitive_types()),
            "requested_sensitive_types": self._requested_sensitive_types(),
            "max_severity": self._max_severity(),
            "confidence": round(self.final.confidence, 2),
            "agent_name": agent_name,
            "judge_score": judge_score,
            "judge_verdict": judge_verdict,
            "judge_reason": judge_reason,
            "judge_mode": judge_mode,
            "needs_review": needs_review,
            "stages": [s.to_dict() for s in self.stages],
        }

    def _reason_codes(self) -> List[str]:
        """Structured codes: one per distinct risk type + the decision itself."""
        codes = {r.risk_type.upper() for r in self.detected_risks}
        codes.add(f"DECISION_{self.decision.value.upper()}")
        return sorted(codes)

    def _max_severity(self) -> str:
        order = {"low": 1, "medium": 2, "high": 3}
        best = max((r.severity.value for r in self.detected_risks),
                   key=lambda s: order.get(s, 0), default="none")
        return best

    def _reason_code(self) -> Optional[str]:
        """A single, coarse machine code summarising the disclosure outcome."""
        types = [r.risk_type for r in self.detected_risks]
        secret_types = ("api_key", "bearer_token", "password", "cvv", "pin", "credit_card")
        has_secret = any(any(s in t for s in secret_types) for t in types)
        if "input_too_large" in types:
            return "input_too_large"
        if any(t.startswith("disclosure_request:") for t in types):
            return "sensitive_data_disclosure_request"
        if any("external_sensitive" in t for t in types):
            return "external_sensitive_data_blocked"
        if self.decision == Decision.BLOCK and has_secret:
            return "secret_disclosure_blocked"
        if any(t.startswith("sensitive_data:") for t in types):
            return "sensitive_pii_disclosure"
        return None

    def _sensitive_types(self) -> List[str]:
        """The distinct sensitive-data types the firewall saw in the raw content
        (authoritative — the audit entry itself only stores redacted text)."""
        return sorted({r.risk_type.split(":", 1)[1] for r in self.detected_risks
                       if r.risk_type.startswith("sensitive_data:")})

    def _requested_sensitive_types(self) -> List[str]:
        """Sensitive field categories the user asked the agent to disclose."""
        return sorted({r.risk_type.split(":", 1)[1] for r in self.detected_risks
                       if r.risk_type.startswith("disclosure_request:")})


class AgentShield:
    """The prompt-injection firewall.

    Parameters
    ----------
    use_llm_detector : bool
        Layer the optional Gemini injection detector on top of the rules. Defaults
        to config; safely no-ops without an API key.
    log : bool
        Whether to append an audit record on each inspection.
    """

    def __init__(self, use_llm_detector: Optional[bool] = None, log: bool = True):
        self.detector = InjectionDetectorAgent(use_llm=use_llm_detector)
        self.log = log
        # Deterministic (offline) independent soundness auditor whose score is
        # attached to every audit-log entry. use_llm=False keeps logging free of
        # any Gemini call regardless of the judge flag.
        from agents.judge_agent import JudgeAgent
        self._audit_judge = JudgeAgent(use_llm=False)

    def _judged_audit(self, result: "FirewallResult", **kw) -> Dict[str, Any]:
        """audit_dict() with the JudgeAgent's independent soundness fields filled."""
        j = self._audit_judge.audit(result)          # soundness only, no expected
        return result.audit_dict(judge_score=j.score, judge_verdict=j.verdict,
                                 judge_reason=j.reason, judge_mode="rules",
                                 needs_review=j.needs_review, **kw)

    # -- primary entry point used by the eval runner ------------------------ #
    def inspect_case(self, case: Case, session_id: str = "") -> FirewallResult:
        return self.inspect(
            user_input=case.user_input,
            context=case.optional_context,
            context_source=case.source,
            tool_call=ToolCall.from_obj(case.planned_tool_call),
            case_id=case.case_id,
            session_id=session_id or case.case_id,
            user_request_summary=case.title,
        )

    @staticmethod
    def _check_size(user_input: str, context: str, context_source: str):
        """Return a BLOCK FirewallDecision if any input exceeds its size limit,
        else None. Fail-closed; reports only lengths, never the raw content."""
        def block(reason: str) -> FirewallDecision:
            return FirewallDecision(
                Decision.BLOCK, [reason], stage="input_size",
                risks=[RiskFinding("input_too_large", Severity.HIGH,
                                   Source.CUSTOMER_TICKET, reason, detector="rules"),
                       RiskFinding("resource_exhaustion_protection", Severity.HIGH,
                                   Source.CUSTOMER_TICKET, reason, detector="rules")])

        ui = len(user_input or "")
        cx = len(context or "")
        if ui > CONFIG.max_user_input_chars:
            return block(f"user input {ui} chars exceeds limit "
                         f"{CONFIG.max_user_input_chars}")
        if cx:
            src = _SOURCE_MAP.get(context_source, Source.TOOL_RESPONSE)
            if src == Source.TOOL_RESPONSE and cx > CONFIG.max_tool_response_chars:
                return block(f"tool-response context {cx} chars exceeds limit "
                             f"{CONFIG.max_tool_response_chars}")
            if src in (Source.ATTACHMENT, Source.EMAIL_THREAD, Source.KNOWLEDGE_BASE) \
                    and cx > CONFIG.max_attachment_chars:
                return block(f"{src.value} context {cx} chars exceeds limit "
                             f"{CONFIG.max_attachment_chars}")
        if ui + cx > CONFIG.max_total_context_chars:
            return block(f"total context {ui + cx} chars exceeds limit "
                         f"{CONFIG.max_total_context_chars}")
        return None

    # -- the actual pipeline ------------------------------------------------ #
    def inspect(
        self,
        user_input: str = "",
        context: str = "",
        context_source: str = "customer_ticket",
        tool_call: Optional[ToolCall] = None,
        final_output: Optional[str] = None,
        case_id: str = "",
        session_id: str = "",
        user_request_summary: str = "",
    ) -> FirewallResult:
        # Stage 0 — fail-closed input-size limits. Over-limit input is BLOCKED
        # here, BEFORE any detection, tool call, or Gemini call — never silently
        # truncated. This bounds cost/DoS and closes the "pad past the scan cap"
        # evasion (hiding an injection after a huge benign prefix).
        oversize = self._check_size(user_input, context, context_source)
        if oversize is not None:
            result = FirewallResult(
                decision=Decision.BLOCK, final=oversize, stages=[oversize],
                case_id=case_id, session_id=session_id, source=context_source,
                planned_tool=tool_call.name if tool_call else None,
                detected_risks=oversize.risks)
            if self.log:
                # Log length metadata only — never the raw over-long input.
                write_entry(self._judged_audit(
                    result,
                    user_request_summary=f"[input too large] {oversize.reasons[0]}"))
            return result

        stages: List[FirewallDecision] = []
        risks: List[RiskFinding] = []

        # Stage 1 — the user's own message (always treated as a direct source).
        d_input = evaluate_text(user_input, Source.CUSTOMER_TICKET, stage="input")
        # Fold in the (optional) LLM detector's opinion on the user message.
        d_input = self.detector.review(user_input, Source.CUSTOMER_TICKET, d_input)
        stages.append(d_input)
        risks.extend(d_input.risks)

        # Stage 2 — any retrieved/attached context, judged by its real source.
        if context and context.strip():
            ctx_source = _SOURCE_MAP.get(context_source, Source.TOOL_RESPONSE)
            # If the case's declared source is "direct", the context still isn't
            # the user typing — treat it as indirect tool_response by default.
            if ctx_source == Source.CUSTOMER_TICKET:
                ctx_source = Source.TOOL_RESPONSE
            d_ctx = evaluate_text(context, ctx_source, stage="context")
            d_ctx = self.detector.review(context, ctx_source, d_ctx)
            stages.append(d_ctx)
            risks.extend(d_ctx.risks)

        # Stage 3 — the planned dry-run tool call.
        if tool_call is not None and tool_call.name:
            d_tool = evaluate_tool_call(tool_call, user_input=user_input, stage="tool_call")
            stages.append(d_tool)
            risks.extend(d_tool.risks)

        # Stage 4 — (optional) inspect a drafted reply before it leaves.
        if final_output is not None:
            d_out = evaluate_output(final_output, stage="output")
            stages.append(d_out)
            risks.extend(d_out.risks)

        final = most_restrictive(stages)

        result = FirewallResult(
            decision=final.decision,
            final=final,
            stages=stages,
            case_id=case_id,
            session_id=session_id,
            source=context_source,
            planned_tool=tool_call.name if tool_call else None,
            detected_risks=risks,
        )

        if self.log:
            write_entry(self._judged_audit(result,
                                           user_request_summary=user_request_summary))

        return result
