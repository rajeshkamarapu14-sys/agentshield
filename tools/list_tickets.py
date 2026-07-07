"""list_tickets_dry_run — list a customer's support tickets (read-only).

Returns the customer's tickets (benign metadata: subject, status, priority).
Low-risk; still firewall-gated like every tool. All data is synthetic.
"""

from __future__ import annotations

from typing import Any, Dict

from tools._synthetic_data import get_tickets

NAME = "list_tickets_dry_run"


def run(customer_id: str = "", **_: Any) -> Dict[str, Any]:
    tickets = get_tickets(customer_id)
    lines = [f"[{t['ticket_id']}] {t['subject']} ({t['priority']}, {t['status']})"
             for t in tickets]
    return {
        "tool": NAME,
        "dry_run": True,
        "customer_id": customer_id,
        "tickets": tickets,
        "text": "\n".join(lines) or "No tickets found.",
    }
