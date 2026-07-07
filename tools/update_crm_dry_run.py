"""update_crm_dry_run — SIMULATE a CRM record update. Never mutates anything.

Risky tool: the firewall requires human approval for customer-record changes and
blocks bulk destructive operations. This stub only echoes what *would* change.
"""

from __future__ import annotations

from typing import Any, Dict

NAME = "update_crm_dry_run"


def run(customer_id: str = "", fields: Dict[str, Any] = None, **kwargs: Any) -> Dict[str, Any]:
    fields = fields or {k: v for k, v in kwargs.items() if k != "record_id"}
    return {
        "tool": NAME,
        "dry_run": True,
        "would_update": {"customer_id": customer_id, "fields": fields},
        "status": "SIMULATED — no CRM record was modified",
    }
