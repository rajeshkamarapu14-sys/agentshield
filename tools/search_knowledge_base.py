"""search_knowledge_base — read-only KB lookup (dry-run).

Returns synthetic FAQ/policy docs. Some docs are poisoned with embedded
injection payloads on purpose; the firewall inspects tool responses precisely
because a KB can be a source of indirect prompt injection.
"""

from __future__ import annotations

from typing import Any, Dict

from tools._synthetic_data import search_kb_records

NAME = "search_knowledge_base"


def run(query: str = "", **_: Any) -> Dict[str, Any]:
    records = search_kb_records(query)
    combined = "\n\n".join(
        f"[{r.get('doc_id', r.get('id', '?'))}] {r.get('title', '')}: "
        f"{r.get('content', r.get('body', ''))}" for r in records)
    return {
        "tool": NAME,
        "dry_run": True,
        "query": query,
        "records": records,
        "text": combined,   # firewall inspects this as source=tool_response
    }
