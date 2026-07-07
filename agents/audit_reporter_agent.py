"""
AuditReporterAgent — turns the JSONL audit trail into a readable report.

Reads logs/audit_log.jsonl and summarises: decision counts, top detected risk
types, and per-entry one-liners. Used by the demo/app to render the audit view
without anyone having to eyeball raw JSON.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from audit import read_entries


class AuditReporterAgent:
    name = "AuditReporterAgent"

    def summarize(self, entries: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        entries = entries if entries is not None else read_entries()
        decisions = Counter(e.get("decision", "unknown") for e in entries)
        risk_types: Counter = Counter()
        severities: Counter = Counter()
        reason_codes: Counter = Counter()
        confidences: List[float] = []
        for e in entries:
            for r in e.get("detected_risks", []):
                risk_types[r.get("risk_type", "unknown")] += 1
            severities[e.get("max_severity", "none")] += 1
            for code in e.get("reason_codes", []):
                reason_codes[code] += 1
            if isinstance(e.get("confidence"), (int, float)):
                confidences.append(float(e["confidence"]))
        avg_conf = round(sum(confidences) / len(confidences), 2) if confidences else None
        return {
            "total": len(entries),
            "by_decision": dict(decisions),
            "by_severity": dict(severities),
            "avg_confidence": avg_conf,
            "top_risks": risk_types.most_common(8),
            "top_reason_codes": reason_codes.most_common(8),
        }

    def render_text(self, entries: List[Dict[str, Any]] = None) -> str:
        entries = entries if entries is not None else read_entries()
        summary = self.summarize(entries)
        lines = ["=== AgentShield Audit Report ===",
                 f"Total decisions logged: {summary['total']}",
                 f"By decision:  {summary['by_decision']}",
                 f"By severity:  {summary['by_severity']}",
                 f"Avg firewall confidence: {summary['avg_confidence']}",
                 f"Top risks: {summary['top_risks']}", "", "Recent entries:"]
        for e in entries[-10:]:
            codes = ",".join(e.get("reason_codes", [])[:3])
            lines.append(
                f"  [{e.get('case_id','?')}] {e.get('decision','?').upper():<22} "
                f"sev={e.get('max_severity','none'):<6} "
                f"{(e.get('user_request_summary') or '')[:38]:<38} {codes}")
        return "\n".join(lines)
