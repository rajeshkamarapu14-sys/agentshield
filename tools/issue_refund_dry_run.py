"""issue_refund_dry_run — SIMULATE issuing a refund. Never moves money.

Risky financial tool. The firewall validates the *amount argument* against a
business threshold: small refunds auto-approve, mid-size refunds need a human,
and absurd amounts are blocked outright (see policy_engine._evaluate_refund).
This stub only echoes what would happen.
"""

from __future__ import annotations

from typing import Any, Dict

NAME = "issue_refund_dry_run"


def run(customer_id: str = "", amount: Any = 0, reason: str = "", **_: Any) -> Dict[str, Any]:
    return {
        "tool": NAME,
        "dry_run": True,
        "would_refund": {"customer_id": customer_id, "amount": amount, "reason": reason},
        "status": "SIMULATED — no money was moved",
    }
