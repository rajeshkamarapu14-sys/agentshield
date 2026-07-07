"""get_security_policy — return the written support-agent security policy (read).

Read-only. Lets agents (and the demo) surface the policy the firewall enforces.
"""

from __future__ import annotations

from typing import Any, Dict

from tools._synthetic_data import SECURITY_POLICY

NAME = "get_security_policy"


def run(**_: Any) -> Dict[str, Any]:
    return {"tool": NAME, "dry_run": True, "text": SECURITY_POLICY}
