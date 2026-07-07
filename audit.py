"""
audit.py — Append-only JSONL audit trail.

Every firewall decision is written as one JSON object per line to
logs/audit_log.jsonl. JSONL is chosen so the log is streamable, greppable, and
trivially machine-readable by the AuditReporterAgent and the eval runner.

Timestamps: the environment used to build this project disallows nondeterministic
clock calls in some contexts, so we read the wall clock defensively and fall back
to an empty string rather than ever crashing the pipeline over a log line.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Set, Tuple

from guardrails.sensitive_data import redact_sensitive_data

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_PATH = os.path.join(LOG_DIR, "audit_log.jsonl")

# Field names that (if present) are treated as free-text carrying possible PII —
# used only to populate `redacted_fields`; ALL string values are redacted anyway.
_SENSITIVE_FIELDS = {"user_request", "user_request_summary", "tool_args",
                     "tool_result", "final_output", "reason", "reasons"}


def _deep_redact(obj: Any) -> Tuple[Any, Set[str]]:
    """Recursively redact every string value; return (clean_obj, types_found)."""
    if isinstance(obj, str):
        cleaned, types = redact_sensitive_data(obj)
        return cleaned, set(types)
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        found: Set[str] = set()
        for k, v in obj.items():
            rv, t = _deep_redact(v)
            out[k] = rv
            found |= t
        return out, found
    if isinstance(obj, list):
        out_list = []
        found = set()
        for v in obj:
            rv, t = _deep_redact(v)
            out_list.append(rv)
            found |= t
        return out_list, found
    return obj, set()


def _now_iso() -> str:
    try:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
    except Exception:  # pragma: no cover
        return ""


def write_entry(entry: Dict[str, Any], path: str = LOG_PATH) -> Dict[str, Any]:
    """Append one audit record, REDACTED. Never writes raw sensitive values.

    Every string value in the entry (user_request, tool_args, tool_result,
    final_output, reason, and any nested metadata) is passed through
    redact_sensitive_data before writing. Adds disclosure metadata:
    redaction_applied, redacted_fields, sensitive_types_detected.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    entry.setdefault("timestamp", _now_iso())

    # Redact per top-level field so we can report which fields changed.
    redacted: Dict[str, Any] = {}
    all_types: Set[str] = set()
    changed_fields: List[str] = []
    for key, value in entry.items():
        rv, types = _deep_redact(value)
        redacted[key] = rv
        if types:
            all_types |= types
            if json.dumps(rv, sort_keys=True, default=str) != \
               json.dumps(value, sort_keys=True, default=str):
                changed_fields.append(key)

    # Union what we redacted here with what the firewall already detected in the
    # raw content (the entry only stores redacted text, so the caller's list is
    # authoritative for types that never appear verbatim in the log).
    prior = set(entry.get("sensitive_types_detected") or [])
    all_types |= prior
    redacted["redacted_fields"] = sorted(changed_fields)
    # True whenever the disclosure policy engaged (sensitive data was present),
    # so logs can be filtered for any request that touched sensitive data.
    redacted["redaction_applied"] = bool(changed_fields or all_types)
    redacted["sensitive_types_detected"] = sorted(all_types)

    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(redacted, ensure_ascii=False) + "\n")
    return redacted


def read_entries(path: str = LOG_PATH) -> List[Dict[str, Any]]:
    """Load all audit records (skips blank/corrupt lines defensively)."""
    if not os.path.exists(path):
        return []
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def clear(path: str = LOG_PATH) -> None:
    """Truncate the log (used by the eval runner for a clean run)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w", encoding="utf-8").close()
