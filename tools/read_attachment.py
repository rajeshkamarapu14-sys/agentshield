"""read_attachment — read a customer-uploaded attachment (dry-run).

Now reads **real files** from data/attachments/ on disk (path-traversal guarded),
falling back to the in-memory synthetic set for any legacy names. Some attachments
carry hidden instructions or fake secrets, demonstrating injection/PII arriving via
an uploaded file — the firewall inspects the returned text as source=attachment.
"""

from __future__ import annotations

import os
from typing import Any, Dict

from tools._synthetic_data import ATTACHMENTS

NAME = "read_attachment"

# Real on-disk attachment store. Reads are confined to this directory.
ATTACHMENT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "data", "attachments")


def _safe_path(name: str) -> str:
    """Resolve `name` inside ATTACHMENT_DIR, rejecting path traversal.

    Prevents `../../etc/passwd`-style escapes: we take only the basename and then
    verify the resolved path is still under ATTACHMENT_DIR.
    """
    base = os.path.basename(name or "")
    candidate = os.path.realpath(os.path.join(ATTACHMENT_DIR, base))
    root = os.path.realpath(ATTACHMENT_DIR)
    if candidate != root and not candidate.startswith(root + os.sep):
        return ""  # traversal attempt → refuse
    return candidate


def run(name: str = "", **_: Any) -> Dict[str, Any]:
    # 1) Try a real file on disk first.
    path = _safe_path(name)
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            return {"tool": NAME, "dry_run": True, "name": os.path.basename(path),
                    "source_path": os.path.relpath(path, os.path.dirname(ATTACHMENT_DIR)),
                    "text": text}
        except OSError as exc:  # pragma: no cover - defensive
            return {"tool": NAME, "dry_run": True, "name": name,
                    "error": f"could not read file: {exc}", "text": ""}

    # 2) Fall back to the in-memory synthetic set (legacy names like *.pdf).
    record = ATTACHMENTS.get(name)
    if record is not None:
        return {"tool": NAME, "dry_run": True, "name": name, "text": record["body"]}

    return {"tool": NAME, "dry_run": True, "name": name,
            "error": "attachment not found", "text": ""}
