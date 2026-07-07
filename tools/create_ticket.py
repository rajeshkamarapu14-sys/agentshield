"""create_ticket — SIMULATE creating an internal support ticket (dry-run).

Low-risk internal write. Returns a deterministic synthetic ticket id (no random
source so eval runs are reproducible).
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict

NAME = "create_ticket"


def run(title: str = "", body: str = "", priority: str = "normal", **_: Any) -> Dict[str, Any]:
    # Deterministic id derived from the title. Uses a stable hash (not Python's
    # per-process-randomised hash()) so the same title yields the same id across
    # processes and runs — important for reproducible evals.
    digest = int(hashlib.sha256(title.encode("utf-8")).hexdigest(), 16)
    ticket_id = "TCK-" + str(digest % 10000).zfill(4)
    return {
        "tool": NAME,
        "dry_run": True,
        "ticket": {"id": ticket_id, "title": title, "priority": priority, "body": body},
        "status": "SIMULATED — internal ticket recorded (dry-run)",
    }
