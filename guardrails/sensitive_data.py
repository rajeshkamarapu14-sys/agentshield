"""
sensitive_data.py — Detect, classify, mask, and redact secrets / PII.

This module implements AgentShield's **sensitive-data disclosure policy**. Every
recognised type has:
  * a detection pattern,
  * a severity,
  * a redaction label (e.g. [REDACTED_DOB]),
  * a policy action — one of: allow | mask | redact | block.

Policy actions (from strongest data-handling requirement to weakest):
  block   — full card, CVV, PIN, password, API key/token/secret. Never disclosed;
            in output they are redacted, and sending them externally is blocked.
  redact  — DOB, phone, home address, passport, NRIC, SSN, national ID. Replaced
            with a label by default.
  mask    — email address. Partially masked (a***@example.com) rather than removed.
  allow   — username alone. Detected/logged but not itself redacted or blocked.

Public API:
  detect_sensitive(text)        -> list[RiskFinding]
  redact_sensitive_data(text)   -> (clean_text, [types_redacted])
  redact(text)                  -> (clean_text, [labels])   (back-compat alias)
  mask_email(text)              -> text with emails masked
  classify_actions(text)        -> (strictest_action, [types_detected])

All example data in this project is SYNTHETIC. These patterns exist to prove the
firewall would catch the real thing — no real customer data should be entered.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Pattern, Tuple

from common import MAX_INSPECT_CHARS, RiskFinding, Severity, Source

# Policy-action ordering (strictest wins when several types co-occur).
_ACTION_RANK = {"allow": 0, "mask": 1, "redact": 2, "block": 3}

# (type, pattern, redaction_label, severity, action)
_PATTERNS: List[Tuple[str, Pattern[str], str, Severity, str]] = [
    # ---- Secrets / credentials (action: block) ----
    (
        "api_key",
        re.compile(r"\b(sk-[A-Za-z0-9_\-]{16,}|AIza[A-Za-z0-9_\-]{20,}"
                   r"|AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{20,}"
                   r"|xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        "[REDACTED_SECRET]", Severity.HIGH, "block",
    ),
    (
        "bearer_token",
        re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}\b", re.I),
        "[REDACTED_SECRET]", Severity.HIGH, "block",
    ),
    (
        "password",
        re.compile(r"\b(password|passwd|pwd|secret)\s*[:=]\s*\S{4,}", re.I),
        "[REDACTED_SECRET]", Severity.HIGH, "block",
    ),
    (
        "cvv",
        re.compile(r"\b(cvv|cvc|cvv2|security\s+code)\b\s*[:#=]?\s*\d{3,4}\b", re.I),
        "[REDACTED_SECRET]", Severity.HIGH, "block",
    ),
    (
        "pin",
        re.compile(r"\bpin\b\s*[:#=]?\s*\d{4,6}\b", re.I),
        "[REDACTED_SECRET]", Severity.HIGH, "block",
    ),
    # ---- Financial (action: block) ----
    (
        "credit_card",
        # Anchored to end on a digit (not a separator) so redaction doesn't
        # swallow the following space: "card 4111 1111 1111 1111 and" stays
        # "[REDACTED_CARD] and", not "[REDACTED_CARD]and".
        re.compile(r"\b\d(?:[ -]?\d){12,15}\b"),
        "[REDACTED_CARD]", Severity.HIGH, "block",
    ),
    # ---- Government / national IDs (action: redact) ----
    (
        "ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "[REDACTED_NATIONAL_ID]", Severity.HIGH, "redact",
    ),
    (
        "nric",
        # Singapore NRIC/FIN: [STFG] + 7 digits + checksum letter.
        re.compile(r"\b[STFGstfg]\d{7}[A-Za-z]\b"),
        "[REDACTED_NATIONAL_ID]", Severity.HIGH, "redact",
    ),
    (
        "passport",
        re.compile(r"passport[^A-Za-z0-9]{0,12}([A-Z]{1,2}\d{6,9})\b", re.I),
        "[REDACTED_NATIONAL_ID]", Severity.HIGH, "redact",
    ),
    (
        "national_id",
        re.compile(r"\b(national\s+id|nric|ic\s+number|identity\s+card|id\s+number)"
                   r"\s*[:#=]?\s*([A-Z0-9]{6,12})\b", re.I),
        "[REDACTED_NATIONAL_ID]", Severity.HIGH, "redact",
    ),
    (
        "iban",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        "[REDACTED_NATIONAL_ID]", Severity.HIGH, "redact",
    ),
    (
        # Non-IBAN bank / routing / account numbers — context-anchored so we don't
        # flag order ids. Blocked-class (financial).
        "bank_account",
        re.compile(r"\b(?:bank\s+account|account\s+(?:number|no\.?|#)|acct\s+(?:number|no\.?|#)"
                   r"|routing\s+(?:number|no\.?)|sort\s+code|a/c\s+no\.?)\b"
                   r"[^\d\n]{0,15}?"          # tolerate "is", ", ", "number is" etc.
                   r"(\d[\d\s-]{5,}\d)", re.I),
        "[REDACTED_BANK]", Severity.HIGH, "block",
    ),
    # ---- Other PII (action: redact) ----
    (
        # Medical info — context-anchored keyword + value. Excludes negations
        # ("prescribed nothing"); the capture stops at a comma/period so it can't
        # swallow an adjacent financial/legal span in the same sentence.
        "medical_info",
        re.compile(r"\b(?:diagnosis|diagnosed\s+with|prescribed|prescription|"
                   r"medical\s+condition|blood\s+type|allergic\s+to)\b\s*[:\-]?\s*"
                   r"(?!(?:nothing|none|no|nil|n/?a|any|unknown)\b)"
                   r"([A-Za-z][A-Za-z0-9 '\-]{2,30})", re.I),
        "[REDACTED_MEDICAL]", Severity.MEDIUM, "redact",
    ),
    (
        # Financial info (salary / income / net worth) — context-anchored + amount.
        "financial_info",
        re.compile(r"\b(?:salary|annual\s+income|monthly\s+income|income|net\s+worth)\b"
                   r"\s*(?:is|of|:)?\s*(?:\$|sgd|usd|s\$)?\s*([\d][\d,]{2,})", re.I),
        "[REDACTED_FINANCIAL]", Severity.MEDIUM, "redact",
    ),
    (
        # Legal info — context-anchored. The value must be a code (digit-led,
        # e.g. "12345-CV") or a capitalised case name (e.g. "Smith v Jones"), so
        # benign prose ("case number for my order", "case is pending") is ignored.
        "legal_info",
        # Keyword is case-insensitive (scoped (?i:...)); the value stays
        # case-sensitive so a capitalised case name is required (else a digit code).
        re.compile(r"(?i:\b(?:court\s+case|case\s+(?:number|no\.?|ref(?:erence)?|#)"
                   r"|litigation|legal\s+(?:case|matter|proceeding))\b\s*[:\-#]?\s*)"
                   r"(\d[\w\-/]{1,20}|[A-Z][A-Za-z]+(?:\s+v\.?\s+[A-Z][A-Za-z]+)?"
                   r"(?:\s+\d{2,4})?)"),
        "[REDACTED_LEGAL]", Severity.MEDIUM, "redact",
    ),
    (
        "dob",
        # Context-anchored so we don't flag every date (order dates, etc.). Allows
        # a few filler words between the label and the date ("DOB is 1990-05-12").
        re.compile(r"\b(dob|d\.?o\.?b\.?|date\s+of\s+birth|birth\s*date|born(?:\s+on)?)\b"
                   r"[^\d\n]{0,25}?(\d{1,4}[-/.]\d{1,2}[-/.]\d{2,4})", re.I),
        "[REDACTED_DOB]", Severity.MEDIUM, "redact",
    ),
    (
        "address",
        # Obvious street address: number (optional unit letter) + words + a
        # street-type suffix, e.g. "221B Baker Street", "10 Downing St".
        re.compile(r"\b\d{1,5}[A-Za-z]?\s+[A-Za-z0-9.\s]{2,30}?\b"
                   r"(street|st|road|rd|avenue|ave|lane|ln|boulevard|blvd|drive|dr"
                   r"|court|ct|way|close|crescent)\b\.?", re.I),
        "[REDACTED_ADDRESS]", Severity.MEDIUM, "redact",
    ),
    (
        "phone",
        # International (spaceless or spaced) or US-grouped. Anchored so it won't
        # grab bare order ids or dates.
        re.compile(r"(?<![\w+])(?:"
                   r"\+\d{7,14}"                            # +6581234567
                   r"|\+\d{1,3}[\s.-]\d{2,4}[\s.-]\d{3,4}"  # +65 8123 4567
                   r"|\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}"    # (415) 555-0199
                   r")(?!\d)"),
        "[REDACTED_PHONE]", Severity.MEDIUM, "redact",
    ),
    # ---- Low-risk / allowed ----
    (
        "username",
        # Context-anchored. Policy action = allow (detected & logged, not redacted
        # by default) — a username alone is not disclosure-blocking PII.
        re.compile(r"\b(?:user\s?name|user\s?id|userid|login|account\s?name)"
                   r"\s*[:=]\s*(\S{2,40})", re.I),
        "[REDACTED_USERNAME]", Severity.LOW, "allow",
    ),
    (
        "email_address",
        # Policy action = mask (a***@example.com), not full redaction.
        re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
        "[REDACTED_EMAIL]", Severity.LOW, "mask",
    ),
]


def detect_sensitive(text: str, source: Source = Source.OUTPUT) -> List[RiskFinding]:
    """Return a RiskFinding for each distinct sensitive type present."""
    if not text:
        return []
    text = text[:MAX_INSPECT_CHARS]  # DoS guard (see common.MAX_INSPECT_CHARS)
    findings: List[RiskFinding] = []
    for ptype, pattern, _label, sev, _action in _PATTERNS:
        m = pattern.search(text)
        if m:
            findings.append(RiskFinding(
                risk_type=f"sensitive_data:{ptype}", severity=sev,
                source=source, evidence=_mask(m.group(0)), detector="rules"))
    return findings


def redact_sensitive_data(text: str) -> Tuple[str, List[str]]:
    """Apply the disclosure policy to `text`.

    Returns (clean_text, types_transformed). Emails are masked (a***@example.com);
    everything with action redact/block is replaced by its label; usernames
    (action=allow) are left intact.
    """
    if not text:
        return text, []
    out = text
    types: List[str] = []
    for ptype, pattern, label, _sev, action in _PATTERNS:
        if action == "allow":
            continue
        if not pattern.search(out):
            continue
        if action == "mask" and ptype == "email_address":
            out = pattern.sub(lambda m: _mask_one_email(m.group(0)), out)
        else:
            out = pattern.sub(label, out)
        types.append(ptype)
    return out, types


def redact(text: str) -> Tuple[str, List[str]]:
    """Back-compat alias used across the codebase (sanitize paths, log hygiene)."""
    return redact_sensitive_data(text)


def mask_email(text: str) -> str:
    """Return `text` with every email partially masked (a***@example.com)."""
    return _EMAIL_RE.sub(lambda m: _mask_one_email(m.group(0)), text)


def classify_actions(text: str) -> Tuple[str, List[str]]:
    """Return (strictest_policy_action, [types_detected]).

    action is one of allow|mask|redact|block ('allow' when nothing detected).
    """
    if not text:
        return "allow", []
    text = text[:MAX_INSPECT_CHARS]
    detected: List[str] = []
    strongest = "allow"
    for ptype, pattern, _label, _sev, action in _PATTERNS:
        if pattern.search(text):
            detected.append(ptype)
            if _ACTION_RANK[action] > _ACTION_RANK[strongest]:
                strongest = action
    return strongest, detected


# --------------------------------------------------------------------------- #
# Generic sensitive-data DISCLOSURE-REQUEST (intent) detection                 #
# --------------------------------------------------------------------------- #
# Detects when a user asks the agent to reveal/share/export sensitive fields,
# even when no actual value is present in the prompt. Generic + schema-aware:
# pass `fields` (e.g. customer JSON keys) to auto-cover future sensitive columns.

# Disclosure verbs incl. common inflections (share/shares/shared/sharing, etc.).
_DISCLOSURE_VERBS = (r"show(?:s|ed|ing|n)?|shar(?:e|es|ed|ing)|reveal(?:s|ed|ing)?"
                     r"|send(?:s|ing)?|sent|export(?:s|ed|ing)?|display(?:s|ed|ing)?"
                     r"|provid(?:e|es|ed|ing)|disclos(?:e|es|ed|ing)|email(?:s|ed|ing)?"
                     r"|forward(?:s|ed|ing)?|dump(?:s|ed|ing)?|giv(?:e|es|ing)|gave|given"
                     r"|tell(?:s|ing)?|told|list(?:s|ed|ing)?|print(?:s|ed|ing)?"
                     r"|get(?:s|ting)?|access(?:es|ed|ing)?|view(?:s|ed|ing)?"
                     r"|se(?:e|es|eing)|saw|leak(?:s|ed|ing)?"
                     r"|pull\s+up|read\s+back|what(?:'?s| is| are)|can\s+you\s+tell\s+me")

# category -> regex of field names / synonyms
_SENSITIVE_FIELD_PATTERNS = {
    "dob": r"d\.?o\.?b\.?|date\s+of\s+birth|birth\s*date|birthday",
    # Email as a PII FIELD (the address), not the communication channel — so
    # "send me an email" (a message) is not mistaken for an address disclosure.
    "email": r"e-?mail\s+(?:address|id|account)"
             r"|(?:my|your|his|her|their|customer'?s?|the)\s+e-?mail\b(?!\s+(?:me|you|to))",
    "phone": r"phone(?:\s+number)?|mobile(?:\s+number)?|contact\s+number|telephone",
    "address": r"(?:home|mailing|residential|postal)\s+address"
               r"|(?<!e-mail )(?<!email )\baddress\b",
    "national_id": r"passport(?:\s+number)?|nric|ssn|social\s+security(?:\s+number)?"
                   r"|national\s+id|identity\s+card|ic\s+number",
    "bank_details": r"bank\s+(?:details|account|account\s+number)|account\s+number"
                    r"|iban|routing\s+number|swift(?:\s+code)?|sort\s+code|bank\s+info",
    "credit_card": r"credit\s+card|card\s+number|full\s+card|card\s+details|debit\s+card|\bpan\b",
    "cvv": r"\bcvv\b|\bcvc\b|security\s+code",
    "pin": r"\bpin\b",
    "password": r"password|passwd|\bpwd\b",
    "api_key": r"api[\s_-]?key|secret\s+key|access\s+token|\btoken\b|\bsecret\b|credentials?",
    "payment_info": r"payment\s+(?:info|information|details)|billing\s+(?:info|information|details)",
    "medical_info": r"medical\s+(?:info|record|history)|health\s+record|diagnosis|prescription",
    "legal_info": r"legal\s+(?:record|info|case)|court\s+record|litigation",
    "financial_info": r"financial\s+(?:info|information|details)|salary|income|net\s+worth|tax\s+(?:id|record)",
}

# category -> policy class (drives the reason code)
_FIELD_CLASS = {
    "dob": "pii", "email": "pii", "phone": "pii", "address": "pii", "national_id": "pii",
    "bank_details": "financial", "credit_card": "financial", "payment_info": "financial",
    "financial_info": "financial",
    "cvv": "secret", "pin": "secret", "password": "secret", "api_key": "secret",
    "medical_info": "medical", "legal_info": "legal",
}
_CLASS_CODE = {
    "pii": "pii_disclosure_blocked",
    "financial": "financial_data_disclosure_blocked",
    "secret": "secret_disclosure_blocked",
    "medical": "medical_data_disclosure_blocked",
    "legal": "legal_data_disclosure_blocked",
}
_LAST4_RE = re.compile(r"last\s*(?:4|four)|card\s+ending|ending\s+in|last4|final\s+4", re.I)
_EXTERNAL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+|external|outside|third[\s-]party"
                          r"|someone\s+else|another\s+(?:person|email)", re.I)
_EXTERNAL_VERB_RE = re.compile(r"\b(?:send|export|email|forward|upload|transmit)\b", re.I)


def _classify_field_name(name: str):
    """Map a raw schema field name to a sensitive category (or None)."""
    n = (name or "").lower()
    tokens = {
        "dob": ["dob", "birth"], "email": ["email"], "phone": ["phone", "mobile"],
        "address": ["address"], "national_id": ["passport", "nric", "ssn", "national_id"],
        "bank_details": ["bank", "iban", "routing", "account_number"],
        "credit_card": ["card", "credit_card", "pan"], "cvv": ["cvv", "cvc"],
        "pin": ["pin"], "password": ["password", "passwd"],
        "api_key": ["api_key", "token", "secret"],
    }
    # last-4 field is safe, not a full-card field
    if "last4" in n or "last_4" in n:
        return None
    for cat, toks in tokens.items():
        if any(t in n for t in toks):
            return cat
    return None


def detect_sensitive_disclosure_request(text: str, fields=None) -> Dict[str, Any]:
    """Detect intent to reveal/share/export sensitive fields (value need not be
    present). Returns sensitive_request_detected / requested_sensitive_types /
    decision / reason_codes.

    `fields`: optional schema field names (e.g. customer JSON keys) — any that
    match a sensitive naming pattern are added, so future columns are auto-covered.
    """
    result: Dict[str, Any] = {
        "sensitive_request_detected": False,
        "requested_sensitive_types": [],
        "decision": "allow",
        "reason_codes": [],
    }
    if not text or not text.strip():
        return result
    low = text[:MAX_INSPECT_CHARS]

    patterns = dict(_SENSITIVE_FIELD_PATTERNS)
    for f in (fields or []):
        cat = _classify_field_name(f)
        if cat:
            phrase = re.escape(str(f).replace("_", " "))
            patterns[cat] = (patterns.get(cat, "") + "|" + phrase) if patterns.get(cat) else phrase

    combined = "|".join(f"(?:{p})" for p in patterns.values())
    # A disclosure VERB bound to a sensitive field within a few words. Filler
    # words may contain apostrophes ("customer's") and span up to 4 tokens.
    verb_bound = re.compile(
        rf"\b(?:{_DISCLOSURE_VERBS})\b(?:\s+[\w']+){{0,4}}?\s+(?:{combined})", re.I)
    if not verb_bound.search(low):
        return result

    last4 = bool(_LAST4_RE.search(low))
    types = []
    for cat, pat in patterns.items():
        if re.search(pat, low, re.I):
            if cat == "credit_card" and last4:
                continue  # only last-4 requested → safe
            types.append(cat)
    if not types:
        return result

    external = bool(_EXTERNAL_VERB_RE.search(low)) and bool(_EXTERNAL_RE.search(low))
    codes = ["sensitive_data_disclosure_request"]
    for cls in sorted({_FIELD_CLASS.get(t, "pii") for t in types}):
        codes.append(_CLASS_CODE[cls])
    if external:
        codes.append("external_sensitive_data_disclosure")

    result.update({
        "sensitive_request_detected": True,
        "requested_sensitive_types": sorted(set(types)),
        "decision": "block",
        "reason_codes": codes,
    })
    return result


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def _mask_one_email(email: str) -> str:
    """john@example.com -> j***@example.com"""
    try:
        local, domain = email.split("@", 1)
    except ValueError:
        return "[REDACTED_EMAIL]"
    first = local[0] if local else ""
    return f"{first}***@{domain}"


def _mask(value: str) -> str:
    """Log-safe representation of a matched value: keep a hint, hide the payload."""
    value = value.strip()
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}…{value[-2:]} (masked)"
