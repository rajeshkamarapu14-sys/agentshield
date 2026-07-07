"""AgentShield multi-agent system.

  SupportAgent            — the tool-using agent being protected
  InjectionDetectorAgent  — detects direct & indirect prompt injection
  ToolPolicyAgent         — enforces tool-use policy on planned calls
  RedTeamAgent            — generates synthetic attack cases for evals
  JudgeAgent              — LLM-as-judge scoring of firewall decisions
  AuditReporterAgent      — turns the JSONL audit trail into a report
"""

from agents.support_agent import SupportAgent
from agents.injection_detector_agent import InjectionDetectorAgent
from agents.tool_policy_agent import ToolPolicyAgent
from agents.red_team_agent import RedTeamAgent
from agents.judge_agent import JudgeAgent
from agents.audit_reporter_agent import AuditReporterAgent

__all__ = [
    "SupportAgent",
    "InjectionDetectorAgent",
    "ToolPolicyAgent",
    "RedTeamAgent",
    "JudgeAgent",
    "AuditReporterAgent",
]
