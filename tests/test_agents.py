"""Dedicated tests for the agents that were previously only exercised live:
ToolPolicyAgent, RedTeamAgent, and AuditReporterAgent. (SupportAgent,
InjectionDetectorAgent, and JudgeAgent are covered in their own test files.)"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import Decision, ToolCall  # noqa: E402
from agents import ToolPolicyAgent, RedTeamAgent, AuditReporterAgent  # noqa: E402


# --- ToolPolicyAgent ---
def test_tool_policy_agent_approves_external_email():
    d = ToolPolicyAgent().check(ToolCall("send_email_dry_run", {"to": "customer@gmail.example"}))
    assert d.decision == Decision.REQUIRE_HUMAN_APPROVAL


def test_tool_policy_agent_blocks_unknown_tool():
    d = ToolPolicyAgent().check(ToolCall("delete_all_customers", {"confirm": "yes"}))
    assert d.decision == Decision.BLOCK


def test_tool_policy_agent_allows_safe_read():
    d = ToolPolicyAgent().check(ToolCall("search_knowledge_base", {"query": "refund policy"}))
    assert d.decision == Decision.ALLOW


# --- RedTeamAgent ---
def test_red_team_agent_generates_structured_cases():
    cases = RedTeamAgent().generate(n=6)
    assert len(cases) == 6
    required = {"case_id", "title", "source", "user_input",
                "expected_decision", "expected_risks"}
    for c in cases:
        assert required.issubset(c.keys())
        assert c["expected_decision"] in {d.value for d in Decision}


def test_red_team_agent_spans_multiple_sources():
    sources = {c["source"] for c in RedTeamAgent().generate(n=10)}
    assert len(sources) >= 2          # not all from a single injection source


# --- AuditReporterAgent ---
_ENTRIES = [
    {"case_id": "T1", "decision": "block", "max_severity": "high",
     "reason_codes": ["DECISION_BLOCK", "INSTRUCTION_OVERRIDE"],
     "user_request_summary": "injection", "confidence": 1.0,
     "detected_risks": [{"risk_type": "instruction_override", "severity": "high"}]},
    {"case_id": "T2", "decision": "allow", "max_severity": "none",
     "reason_codes": ["DECISION_ALLOW"], "user_request_summary": "safe",
     "confidence": 1.0, "detected_risks": []},
]


def test_audit_reporter_summarize():
    s = AuditReporterAgent().summarize(_ENTRIES)
    assert s["total"] == 2
    assert s["by_decision"] == {"block": 1, "allow": 1}
    assert "high" in s["by_severity"]


def test_audit_reporter_render_text():
    txt = AuditReporterAgent().render_text(_ENTRIES)
    assert "AgentShield Audit Report" in txt
    assert "Total decisions logged: 2" in txt
    assert "T1" in txt and "BLOCK" in txt
