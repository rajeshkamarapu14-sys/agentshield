"""draft_customer_reply — compose a support reply (dry-run, no send).

Produces a plain-text draft. The output guardrail inspects this draft before it
could ever be shown/sent, so a reply that accidentally contains a secret or an
echoed injection is caught.
"""

from __future__ import annotations

from typing import Any, Dict

NAME = "draft_customer_reply"


def run(ticket: str = "", notes: str = "", **_: Any) -> Dict[str, Any]:
    body = (
        "Hello,\n\n"
        "Thanks for reaching out. "
        + (notes.strip() if notes else "We're looking into your request and will follow up shortly.")
        + "\n\nBest regards,\nAcme Support"
    )
    return {"tool": NAME, "dry_run": True, "ticket": ticket, "text": body}
