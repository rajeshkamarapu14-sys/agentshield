"""send_email_dry_run — SIMULATE sending an email. Never sends anything.

This is a risky/external tool: the firewall requires human approval for external
recipients and blocks sends that carry sensitive/bulk data. Even when "executed"
here it only returns a simulated receipt.
"""

from __future__ import annotations

from typing import Any, Dict

NAME = "send_email_dry_run"


def run(to: str = "", subject: str = "", body: str = "", **_: Any) -> Dict[str, Any]:
    # DRY-RUN: we deliberately do not import any mail library. This is a stub.
    return {
        "tool": NAME,
        "dry_run": True,
        "would_send": {"to": to, "subject": subject, "body": body},
        "status": "SIMULATED — no email was sent",
    }
