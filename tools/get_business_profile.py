"""get_business_profile_dry_run — return the business/company profile (read-only).

Serves NovaCart Support's synthetic business context (country, currency, refund
policy, thresholds, data-handling policy) so the agent can ground its answers in
the company's rules. Read-only, firewall-gated like every tool. Synthetic data.
"""

from __future__ import annotations

from typing import Any, Dict

from tools._synthetic_data import get_company

NAME = "get_business_profile_dry_run"


def run(**_: Any) -> Dict[str, Any]:
    company = get_company()
    rp = company.get("refund_policy", {})
    text = (
        f"{company.get('company_name', 'Company')} — {company.get('business_type', '')}. "
        f"Country: {company.get('country', '')} ({company.get('country_code', '')}), "
        f"currency {company.get('currency', '')}. "
        f"Refund window: {rp.get('window_days', '')} days. "
        f"Refund types: {', '.join(rp.get('refund_types', []))}. "
        f"Refunds above {rp.get('currency', '')} {rp.get('human_approval_above', '')} "
        f"require human approval."
    )
    return {
        "tool": NAME,
        "dry_run": True,
        "profile": company,
        "text": text,
    }
