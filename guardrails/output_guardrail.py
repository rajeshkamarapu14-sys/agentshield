"""
output_guardrail.py — Final-output safety check.

This is the last gate before a drafted reply would be shown/sent. It is a thin,
clearly-named wrapper over `policy_engine.evaluate_output` so the pipeline reads
naturally (`scan_output(reply)`) and so this concern has its own home in the
guardrails package.

Rules enforced (see policy_engine.evaluate_output for the implementation):
  * reply echoes injected instructions          → BLOCK
  * secrets/credentials/PII in the reply        → SANITIZE (redacted with labels;
                                                  the cleaned reply then proceeds —
                                                  "safe summaries may proceed with
                                                  redacted values")
  * otherwise                                   → ALLOW

Note: external *sending* of sensitive data is blocked at the tool stage
(_evaluate_email); the output guardrail redacts rather than blocks, so a helpful
reply can still be returned with sensitive values masked.
"""

from __future__ import annotations

import html
import shlex

from common import FirewallDecision
from guardrails.policy_engine import evaluate_output


def scan_output(reply: str) -> FirewallDecision:
    """Inspect a final agent reply and return the firewall verdict."""
    return evaluate_output(reply, stage="output")


def encode_output(text: str, context: str = "text") -> str:
    """Context-aware output encoding for the downstream sink (OWASP LLM05).

    The firewall makes a reply *safe to read* (redaction + no echoed injection);
    but whatever consumes the reply must ENCODE it for its own context. This
    helper does that so the consuming app can't forget:

      html  → HTML-escape (prevents XSS when rendered in a browser)
      shell → shell-quote (prevents command injection)
      sql   → NOT provided on purpose — use parameterized queries, never string
              interpolation. Returns the text unchanged with the reminder that
              escaping is not a substitute for prepared statements.
      text  → returned unchanged

    A firewall can't know the sink, so this is a utility the integrator calls —
    it is deliberately not applied automatically.
    """
    if context == "html":
        return html.escape(text, quote=True)
    if context == "shell":
        return shlex.quote(text)
    # "sql" and "text" fall through unchanged (SQL must use bind parameters).
    return text
