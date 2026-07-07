"""
injection_rules.py — Deterministic prompt-injection detection.

This is the core detector. It scans any piece of text (user ticket, attachment,
KB doc, prior email, or a tool's response) for the linguistic fingerprints of a
prompt-injection attempt and returns structured RiskFindings.

Design notes
------------
* Pure regex + keyword rules, no LLM required — so it is fast, free, offline, and
  fully reproducible for the eval harness. The optional LLM detector (see
  agents/injection_detector_agent.py) layers on top of this, never replaces it.
* Patterns are grouped by attack technique so the audit log can name *why* text
  was flagged, not just that it was.
* Indirect injection (source is a document/tool response rather than the user) is
  treated as higher severity: content that arrives from a retrieved document has
  no business issuing instructions to the agent at all.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from typing import List, Pattern, Tuple

from common import MAX_INSPECT_CHARS, RiskFinding, Severity, Source

# Sources that are "data, not instructions". If any of these tries to issue a
# command to the agent, that is by definition indirect prompt injection.
_INDIRECT_SOURCES = {
    Source.ATTACHMENT,
    Source.KNOWLEDGE_BASE,
    Source.EMAIL_THREAD,
    Source.TOOL_RESPONSE,
}


# Each rule: (risk_type, compiled_pattern, base_severity, human_reason)
# NOTE: patterns are intentionally readable over clever; a judge should be able
# to look at this table and understand exactly what the firewall catches.
_RULES: List[Tuple[str, Pattern[str], Severity, str]] = [
    # --- Instruction override / jailbreak framing ---
    (
        "instruction_override",
        re.compile(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b"
                   r"(previous|prior|above|earlier|all)\b[^.\n]{0,20}"
                   r"(instructions?|rules?|prompts?|policy|policies|context)", re.I),
        Severity.HIGH,
        "Text attempts to override prior instructions or policy.",
    ),
    (
        "instruction_override",
        re.compile(r"\b(new|updated|revised)\s+(instructions?|rules?|system\s+prompt)\b", re.I),
        Severity.MEDIUM,
        "Text tries to inject a new instruction/rule set.",
    ),
    (
        # "disregard your rules", "ignore the policy", "bypass any guidelines" —
        # override framed against your/the/any rather than "all previous".
        "instruction_override",
        re.compile(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,12}"
                   r"\b(your|the|my|these|those|all|any)\b[^.\n]{0,10}"
                   r"\b(rules?|instructions?|polic(?:y|ies)|guidelines?|guardrails?"
                   r"|restrictions?|checks?|user|human|caller|operator)\b", re.I),
        Severity.HIGH,
        "Text attempts to override the agent's rules/policy.",
    ),
    (
        "role_manipulation",
        re.compile(r"\byou\s+are\s+now\b|\bpretend\s+to\s+be\b|\bact\s+as\s+(if|an?|the)\b"
                   r"|\bfrom\s+now\s+on\b|\bswitch\s+to\s+.{0,20}mode\b", re.I),
        Severity.MEDIUM,
        "Text attempts to reassign the agent's role or persona.",
    ),
    (
        "jailbreak",
        re.compile(r"\b(dan\s+mode|developer\s+mode|jailbreak|do\s+anything\s+now"
                   r"|no\s+restrictions?|without\s+(any\s+)?(restrictions?|filters?|guardrails?))\b", re.I),
        Severity.HIGH,
        "Known jailbreak framing detected.",
    ),
    # --- System-prompt / hidden-instruction exfiltration ---
    (
        "system_prompt_leak",
        re.compile(r"\b(reveal|show|print|repeat|display|expose|leak|tell\s+me"
                   r"|what(?:'?s| is| are)|give\s+me)\b[^.\n]{0,40}"
                   r"\b(system\s+prompt|hidden\s+(instructions?|rules?|prompt)"
                   r"|initial\s+(instructions?|prompt)|your\s+(instructions?|system\s+prompt)"
                   r"|the\s+prompt\s+above|configuration|guidelines)", re.I),
        Severity.HIGH,
        "Text tries to extract the system prompt or hidden instructions.",
    ),
    # --- Secret / credential extraction ---
    (
        "credential_extraction",
        re.compile(r"\b(api[\s_-]?key|secret|password|token|credential|private\s+key"
                   r"|env(ironment)?\s+variable)s?\b[^.\n]{0,30}"
                   r"\b(show|give|send|reveal|print|share|tell|what|list|dump)\b"
                   r"|\b(show|give|send|reveal|print|share|tell|list|dump)\b[^.\n]{0,30}"
                   r"\b(api[\s_-]?key|secret|password|token|credential|private\s+key)s?\b", re.I),
        Severity.HIGH,
        "Text requests credentials, secrets, or API keys.",
    ),
    # --- Data exfiltration to an external destination ---
    (
        "data_exfiltration",
        re.compile(r"\b(send|email|forward|export|upload|post|leak|exfiltrate|transmit)\b"
                   r"[^.\n]{0,60}\b(customer\s+(data|details|info|information|records?|profile)"
                   r"|all\s+(records?|users?|customers?)"
                   r"|database|the\s+(entire\s+)?(list|table)|personal\s+(data|information)"
                   r"|pii|to\s+[\w.+-]+@[\w-]+"
                   r"|personal\s+(gmail|hotmail|yahoo|outlook|email|inbox|account)"
                   r"|\b(gmail|hotmail|yahoo|outlook)\b"
                   r"|external(?:ly)?|outside|third[\s-]party)", re.I),
        Severity.HIGH,
        "Text instructs sending/exporting data to an external destination.",
    ),
    # --- False-authorization social engineering (esp. in email-thread history) ---
    (
        # "A previous assistant approved sharing DOB and bank details" — a bland,
        # imperative-free claim that a prior party authorized a sensitive
        # disclosure or a policy override. Common in poisoned email threads.
        "false_authorization",
        re.compile(r"\b(previous|prior|earlier|another|last|other|the)\s+"
                   r"(assistant|agent|admin\w*|manager|supervisor|rep\w*|operator|team|staff|bot|ai)\b"
                   r"[^.\n]{0,50}?\b(approv\w+|authoriz\w+|allow\w+|clear\w+|permit\w+"
                   r"|confirm\w+|ok'?d|okay'?d|green.?lit|said|agreed)\b"
                   r"[^.\n]{0,50}?\b(shar\w+|send\w+|disclos\w+|reveal\w+|releas\w+|forward\w+"
                   r"|provid\w+|dob|ssn|bank|account|card|password|credential"
                   r"|customer\s+(data|records?|details?|info\w*)|personal\s+(data|info\w*)|pii"
                   r"|ignore|bypass|overrid\w+)\b", re.I),
        Severity.HIGH,
        "Claims a prior party authorized disclosing sensitive data or overriding policy.",
    ),
    # --- Embedded/hidden instruction markers common in indirect injection ---
    (
        "embedded_instruction",
        re.compile(r"\[(system|instruction|assistant|admin|important)\]"
                   r"|<\s*(system|instruction|important)\s*>"
                   r"|###\s*(system|instruction|override)"
                   r"|note\s+to\s+(the\s+)?(ai|assistant|agent|llm|model)"
                   r"|attention\s+(ai|assistant|agent|model)", re.I),
        Severity.HIGH,
        "Document contains markers that impersonate system/assistant instructions.",
    ),
    (
        "policy_bypass",
        re.compile(r"\b(without|no\s+need\s+for|skip|bypass|don'?t\s+require)\b[^.\n]{0,30}"
                   r"\b(approval|authoriz(e|ation)|verification|confirmation|human\s+review|checks?)\b", re.I),
        Severity.HIGH,
        "Text tries to bypass approval / verification controls.",
    ),
    (
        "unauthorized_action",
        re.compile(r"\b(refund|charge|transfer|delete|wipe|reset|escalat\w+|grant\s+access"
                   r"|make\s+(me|them)\s+(an\s+)?admin)\b[^.\n]{0,40}"
                   r"\b(immediately|now|full|all|without|regardless|no\s+matter)\b", re.I),
        Severity.MEDIUM,
        "Text pushes for a privileged/irreversible action bypassing normal checks.",
    ),
    (
        # Markdown link/image whose URL smuggles data out in the query string —
        # a classic indirect-exfiltration trick ("render this image" → beacon).
        "markdown_exfiltration",
        # Bounded quantifiers (no unbounded adjacent same-class repeats) so a
        # crafted long URL can't trigger catastrophic backtracking (ReDoS).
        re.compile(r"!?\[[^\]]{0,200}\]\(\s*https?://[^)\s]{1,300}?[?&]"
                   r"[^)\s]{0,200}?(data|token|key|secret|prompt|session|cookie|q)=", re.I),
        Severity.HIGH,
        "Markdown link/image smuggles data to an external URL (exfiltration beacon).",
    ),
]

# High-signal keywords in their separator-stripped form. Catches letter-spacing /
# hyphenation obfuscation like "i g n o r e" or "ign-ore all instructions".
_COMPACT_SIGNATURES = {
    "ignoreallprevious": ("instruction_override", Severity.HIGH),
    "ignoreallinstruction": ("instruction_override", Severity.HIGH),
    "ignorepreviousinstruction": ("instruction_override", Severity.HIGH),
    "disregardallprevious": ("instruction_override", Severity.HIGH),
    "revealsystemprompt": ("system_prompt_leak", Severity.HIGH),
    "showsystemprompt": ("system_prompt_leak", Severity.HIGH),
    "developermode": ("jailbreak", Severity.HIGH),
    "doanythingnow": ("jailbreak", Severity.HIGH),
    "exfiltrate": ("data_exfiltration", Severity.HIGH),
}

# Characters used to hide keywords: zero-width, soft/non-breaking hyphens, BOM.
_INVISIBLE = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0xFEFF, 0x00AD, 0x2060], None)

# A few common homoglyphs (Cyrillic/Greek lookalikes) → Latin, so "іgnоre"
# (with Cyrillic і/о) normalises to "ignore" before matching.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "Α": "A", "Ε": "E", "Ο": "O",
    "‑": "-",  # non-breaking hyphen → normal hyphen
}


def detect_injection(text: str, source: Source) -> List[RiskFinding]:
    """Return every injection RiskFinding matched in `text`.

    `source` raises severity by one notch for indirect sources (documents / tool
    responses), because instructions coming from data are inherently suspicious.
    """

    if not text or not text.strip():
        return []

    # Cap the volume any detector will scan (DoS / ReDoS guard).
    text = text[:MAX_INSPECT_CHARS]

    findings: List[RiskFinding] = []
    seen: set = set()  # dedupe identical (risk_type, evidence) hits

    def emit(risk_type: str, base_sev: Severity, evidence: str, tag: str = "") -> None:
        key = (risk_type, evidence.lower()[:60])
        if key in seen:
            return
        seen.add(key)
        severity = _escalate(base_sev) if source in _INDIRECT_SOURCES else base_sev
        findings.append(RiskFinding(
            risk_type=risk_type, severity=severity, source=source,
            evidence=(f"[{tag}] " if tag else "") + evidence, detector="rules"))

    # 1) Raw text against the rule table.
    _scan_rules(text, emit)

    # 2) Normalised text (unicode/homoglyph/zero-width/nb-hyphen + leetspeak
    #    digit folding, e.g. "1gn0re" -> "ignore") — catches obfuscation that
    #    hides an otherwise-plain injection.
    norm = _normalize(text)
    if norm != text:
        _scan_rules(norm, emit, tag="deobfuscated")

    # 3) Flattened text — sentence/newline boundaries collapsed to spaces, so an
    #    injection split across sentences ("Please ignore this. All previous
    #    instructions no longer apply.") can't slip through the `[^.\n]` gaps.
    flat = _flatten(norm)
    if flat != norm:
        _scan_rules(flat, emit, tag="flattened")

    # 4) Base64-encoded payloads: decode candidate blobs and re-scan.
    for decoded in _decode_base64_blobs(text):
        _scan_rules(decoded, lambda rt, sv, ev, tag="base64": emit(rt, sv, ev, "base64"))

    # 5) Hex-encoded payloads (raw "69676e..." or \xNN escapes) → decode + re-scan.
    for decoded in _decode_hex_blobs(text):
        _scan_rules(decoded, lambda rt, sv, ev, tag="hex": emit(rt, sv, ev, "hex"))

    # 6) ROT13 — decode the whole text and re-scan (harmless on normal text: a
    #    ROT13 of English is gibberish that won't match; only a truly ROT13-encoded
    #    injection decodes back to real keywords).
    rot = codecs.encode(text, "rot_13")
    if rot != text:
        _scan_rules(rot, lambda rt, sv, ev, tag="rot13": emit(rt, sv, ev, "rot13"))

    # 7) Letter-spacing / hyphenation obfuscation via compact keyword signatures.
    compact = re.sub(r"[^a-z0-9]", "", norm.lower())
    for sig, (risk_type, sev) in _COMPACT_SIGNATURES.items():
        if sig in compact:
            emit(risk_type, sev, sig, tag="compact")

    return findings


def _decode_hex_blobs(text: str) -> List[str]:
    """Decode raw hex sequences and \\xNN escapes that yield printable ASCII."""
    out: List[str] = []
    # \xNN escaped form, e.g. \x69\x67\x6e...
    esc = re.findall(r"(?:\\x[0-9a-fA-F]{2}){6,}", text)
    for blob in esc:
        try:
            decoded = bytes.fromhex(blob.replace("\\x", "")).decode("ascii", "strict")
            if decoded.isprintable():
                out.append(decoded)
        except (ValueError, UnicodeDecodeError):
            pass
    # Raw hex run, e.g. 69676e6f7265 (optionally space-separated pairs)
    for blob in re.findall(r"\b(?:[0-9a-fA-F]{2}[\s]?){8,}\b", text):
        h = re.sub(r"\s", "", blob)
        if len(h) % 2:
            continue
        try:
            decoded = bytes.fromhex(h).decode("ascii", "strict")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isascii() and sum(c.isalpha() or c.isspace() for c in decoded) >= 0.7 * len(decoded):
            out.append(decoded)
    return out


def _scan_rules(text: str, emit, tag: str = "") -> None:
    """Run the rule table over `text`, calling emit(risk_type, sev, evidence)."""
    for risk_type, pattern, base_sev, _reason in _RULES:
        match = pattern.search(text)
        if match:
            emit(risk_type, base_sev, _snippet(text, match), tag)


# Leetspeak digit/symbol → letter folding (applied only in the detection copy).
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}


def _normalize(text: str) -> str:
    """NFKC-normalise, strip invisible chars, map homoglyphs + leetspeak to Latin.

    Leetspeak folding runs only on the detection copy, so "1gn0re"/"sh0w" collapse
    to real words; it never alters the content the agent actually uses.
    """
    text = text.translate(_INVISIBLE)
    text = unicodedata.normalize("NFKC", text)
    return "".join(_LEET.get(ch, _HOMOGLYPHS.get(ch, ch)) for ch in text)


def _flatten(text: str) -> str:
    """Collapse sentence/clause boundaries (. ; ! ? and newlines) to single
    spaces, defeating payloads split across sentences to dodge `[^.\\n]` gaps."""
    return re.sub(r"\s+", " ", re.sub(r"[.\n;!?]+", " ", text)).strip()


def _decode_base64_blobs(text: str, _depth: int = 0) -> List[str]:
    """Find base64-looking tokens, decode the ones that yield printable text.

    Recurses one level so double-encoded (base64-in-base64) payloads are also
    caught: the outer decode yields an inner base64 string, which we decode again.
    """
    out: List[str] = []
    for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        # Length must be a multiple of 4 to be valid base64.
        if len(token) % 4:
            continue
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = raw.decode("utf-8", errors="strict")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        # Only keep decodes that look like natural-language text (avoid noise).
        if decoded.isascii() and sum(c.isalpha() or c.isspace() for c in decoded) >= 0.7 * len(decoded):
            out.append(decoded)
            if _depth < 1:                      # unwrap one nested layer
                out.extend(_decode_base64_blobs(decoded, _depth + 1))
    return out


def looks_like_injection(text: str, source: Source = Source.CUSTOMER_TICKET) -> bool:
    """Convenience boolean used by tests and quick checks."""
    return len(detect_injection(text, source)) > 0


def _escalate(sev: Severity) -> Severity:
    return {
        Severity.LOW: Severity.MEDIUM,
        Severity.MEDIUM: Severity.HIGH,
        Severity.HIGH: Severity.HIGH,
    }[sev]


def _snippet(text: str, match: "re.Match[str]", pad: int = 20) -> str:
    """Extract a short, log-friendly window around the matched span.

    The window is redacted before returning so that any secret/PII that happens
    to sit next to an injection match never lands raw in a reason string or the
    audit log (evidence is for explaining *what* was caught, not for storing the
    payload verbatim).
    """
    from guardrails.sensitive_data import redact

    start = max(0, match.start() - pad)
    end = min(len(text), match.end() + pad)
    snip = text[start:end].replace("\n", " ").strip()
    snip, _labels = redact(snip)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{snip}{suffix}"
