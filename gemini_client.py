"""
gemini_client.py — Thin, optional wrapper around Google Gemini.

Uses the current **Google GenAI SDK** (`google-genai`, `from google import genai`)
— the package Google now recommends (the older `google-generativeai` is EOL).

The entire firewall runs without this. It exists only so the JudgeAgent and the
InjectionDetectorAgent can *optionally* add an LLM opinion when a GEMINI_API_KEY
is configured. Every function degrades to a safe no-op (returns None) when the
key or SDK is missing, so demos and evals never depend on the network.

This is also the natural seam for a Google ADK agent: an ADK LlmAgent uses the
same SDK + model; see docs/architecture.md for the ADK mapping.
"""

from __future__ import annotations

from typing import Optional

from config import CONFIG

_client_cache = None


def available() -> bool:
    """True only if a key is set and the google-genai SDK imports."""
    return CONFIG.gemini_available


def _get_client():
    global _client_cache
    if _client_cache is not None:
        return _client_cache
    if not available():
        return None
    try:
        from google import genai
        _client_cache = genai.Client(api_key=CONFIG.gemini_api_key)
        return _client_cache
    except Exception:
        return None


def generate(prompt: str, temperature: float = 0.0) -> Optional[str]:
    """Return the model's text response, or None if Gemini is unavailable/errors.

    Callers MUST handle None by falling back to deterministic behaviour.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        resp = client.models.generate_content(
            model=CONFIG.gemini_model,
            contents=prompt,
            config={"temperature": temperature},
        )
        return (resp.text or "").strip()
    except Exception:
        return None
