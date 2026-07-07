"""
config.py — Runtime configuration for AgentShield.

Single source of truth for "are we running purely deterministically, or is the
optional Gemini integration switched on?". Everything degrades gracefully: if no
API key is present, or google-generativeai isn't installed, the LLM flags read as
False and the system runs 100% offline on deterministic rules.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# python-dotenv is a hard dependency but we guard the import so `config` never
# crashes a fresh checkout that hasn't installed requirements yet.
try:
    from dotenv import load_dotenv

    load_dotenv()  # loads a local .env if present; silently no-ops otherwise
except Exception:  # pragma: no cover - defensive only
    pass


def _flag(name: str, default: bool = False) -> bool:
    val = os.getenv(name, str(default)).strip().lower()
    return val in ("1", "true", "yes", "on")


def _num(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Config:
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    use_llm_judge: bool = False
    use_llm_detector: bool = False
    # Per-tool argument-validation thresholds (business policy — NovaCart, SGD).
    # Refunds up to SGD 500 auto-approve; above 500 need a human; above 10k blocked.
    refund_auto_approve_cap: float = 500.0    # refunds <= this auto-approve (SGD)
    refund_block_ceiling: float = 10000.0     # refunds >  this are blocked outright

    # Fail-closed input-size limits (resource-exhaustion / cap-evasion guard).
    # Anything over its limit is BLOCKED before detection/tools/Gemini — never
    # silently truncated. Chars, except the API body which is bytes.
    max_user_input_chars: int = 8000
    max_attachment_chars: int = 50000       # attachment / email_thread content
    max_tool_response_chars: int = 20000
    max_total_context_chars: int = 100000
    max_api_body_bytes: int = 262144        # 256 KB

    @property
    def gemini_available(self) -> bool:
        """True only if a key is set AND the SDK imports successfully."""
        if not self.gemini_api_key:
            return False
        try:
            from google import genai  # noqa: F401  (google-genai SDK)
            return True
        except Exception:
            return False


def load_config() -> Config:
    return Config(
        gemini_api_key=os.getenv("GEMINI_API_KEY", "").strip(),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip(),
        use_llm_judge=_flag("AGENTSHIELD_USE_LLM_JUDGE"),
        use_llm_detector=_flag("AGENTSHIELD_USE_LLM_DETECTOR"),
        refund_auto_approve_cap=_num("AGENTSHIELD_REFUND_AUTO_APPROVE_CAP", 500.0),
        refund_block_ceiling=_num("AGENTSHIELD_REFUND_BLOCK_CEILING", 10000.0),
        max_user_input_chars=int(_num("AGENTSHIELD_MAX_USER_INPUT_CHARS", 8000)),
        max_attachment_chars=int(_num("AGENTSHIELD_MAX_ATTACHMENT_CHARS", 50000)),
        max_tool_response_chars=int(_num("AGENTSHIELD_MAX_TOOL_RESPONSE_CHARS", 20000)),
        max_total_context_chars=int(_num("AGENTSHIELD_MAX_TOTAL_CONTEXT_CHARS", 100000)),
        max_api_body_bytes=int(_num("AGENTSHIELD_MAX_API_BODY_BYTES", 262144)),
    )


# Convenient module-level singleton; import as `from config import CONFIG`.
CONFIG = load_config()
