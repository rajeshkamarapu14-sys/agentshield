"""read_email_thread — read a prior email thread (dry-run).

Reads **real files** from data/email_threads/ on disk (path-traversal guarded),
falling back to the in-memory synthetic set. Email history is prompt-injection
source #4: a malicious instruction can hide in an earlier message. The firewall
inspects the returned text as untrusted content.
"""

from __future__ import annotations

import os
from typing import Any, Dict

from tools._synthetic_data import EMAIL_THREADS

NAME = "read_email_thread"

EMAIL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "data", "email_threads")


def _safe_path(name: str) -> str:
    """Resolve `name` inside EMAIL_DIR, rejecting path traversal."""
    base = os.path.basename(name or "")
    candidate = os.path.realpath(os.path.join(EMAIL_DIR, base))
    root = os.path.realpath(EMAIL_DIR)
    if candidate != root and not candidate.startswith(root + os.sep):
        return ""
    return candidate


def run(name: str = "", **_: Any) -> Dict[str, Any]:
    # 1) Try a real file on disk first.
    path = _safe_path(name)
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            return {"tool": NAME, "dry_run": True, "name": os.path.basename(path),
                    "source_path": os.path.relpath(path, os.path.dirname(EMAIL_DIR)),
                    "text": text}
        except OSError as exc:  # pragma: no cover - defensive
            return {"tool": NAME, "dry_run": True, "name": name,
                    "error": f"could not read file: {exc}", "text": ""}

    # 2) Fall back to the in-memory synthetic set.
    record = EMAIL_THREADS.get(name)
    if record is not None:
        return {"tool": NAME, "dry_run": True, "name": name, "text": record["body"]}

    return {"tool": NAME, "dry_run": True, "name": name,
            "error": "email thread not found", "text": ""}
