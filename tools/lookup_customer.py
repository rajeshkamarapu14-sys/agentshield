"""lookup_customer_dry_run — look up a synthetic customer record (read-only).

Returns the structured record AND a human-readable `text` summary. The summary is
what the firewall inspects on the way back (source=tool_response): sensitive
fields (DOB, phone, address) are redacted and the email is masked automatically,
while the safe card_last4 is left visible — demonstrating the disclosure policy
on real looked-up data.

IMPORTANT: the synthetic store holds NO full card number (card_last4 only), so a
full PAN can never be disclosed — the system cannot leak what it does not store.
All data is synthetic.
"""

from __future__ import annotations

from typing import Any, Dict

from tools._synthetic_data import get_customer

NAME = "lookup_customer_dry_run"


def run(customer_id: str = "", **_: Any) -> Dict[str, Any]:
    record = get_customer(customer_id)
    if not record:
        return {"tool": NAME, "dry_run": True, "customer_id": customer_id,
                "error": "customer not found", "text": ""}

    # Human-readable summary — the firewall redacts/masks the sensitive parts of
    # this text before it reaches the agent (last-4 stays; no full card exists).
    summary = (
        f"Customer {record['customer_id']} — {record['name']} "
        f"({record.get('tier', 'standard')}, {record.get('account_status', 'active')}). "
        f"Email: {record.get('email', '')}. "
        f"Phone: {record.get('phone', '')}. "
        f"DOB: {record.get('dob', '')}. "
        f"Address: {record.get('address', '')}. "
        f"Card ending {record.get('card_last4', '')}."
    )
    # Only non-sensitive fields are exposed in structured form. Sensitive fields
    # (email, phone, dob, address) are NOT returned raw — the firewall would
    # redact them anyway, but we don't hand them out in the first place. No full
    # card exists (last-4 only), so a full PAN can never be disclosed.
    safe_record = {
        "customer_id": record.get("customer_id"),
        "username": record.get("username"),
        "name": record.get("name"),
        "tier": record.get("tier"),
        "account_status": record.get("account_status"),
        "country": record.get("country"),
        "card_last4": record.get("card_last4"),
    }
    return {
        "tool": NAME,
        "dry_run": True,
        "safe_record": safe_record,   # non-sensitive fields only (no raw PII)
        "text": summary,              # inspected + redacted by the firewall on return
    }

