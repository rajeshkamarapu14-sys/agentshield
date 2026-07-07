"""Tests for the sensitive-data disclosure policy (detection, redaction in
final output, and redaction in the audit log)."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import Decision, ToolCall  # noqa: E402
from firewall import AgentShield  # noqa: E402
from guardrails.policy_engine import evaluate_output, evaluate_tool_call  # noqa: E402
from guardrails.sensitive_data import (  # noqa: E402
    classify_actions, redact_sensitive_data, mask_email,
)


# ---- 1. DOB: final response redacts DOB, logs no raw DOB ----
def test_dob_redacted_in_output_and_log(tmp_path):
    reply = "Your date of birth on file is 1990-05-12."
    d = evaluate_output(reply)
    assert d.decision == Decision.SANITIZE
    assert "[REDACTED_DOB]" in d.sanitized_text
    assert "1990-05-12" not in d.sanitized_text

    log = tmp_path / "audit.jsonl"
    from audit import write_entry
    entry = write_entry({"final_output": reply, "user_request": "what's my DOB 1990-05-12"},
                        path=str(log))
    assert "1990-05-12" not in json.dumps(entry)
    assert entry["redaction_applied"] is True
    assert "dob" in entry["sensitive_types_detected"]


# ---- 2. Credit card: blocked externally / redacted, logs no raw card ----
def test_credit_card_blocked_external_and_not_logged_raw(tmp_path):
    d = evaluate_tool_call(ToolCall("send_email_dry_run",
                                    {"to": "x@gmail.com", "body": "card 4111111111111111"}))
    assert d.decision == Decision.BLOCK

    d2 = evaluate_output("Your card number is 4111111111111111.")
    assert d2.decision == Decision.SANITIZE
    assert "[REDACTED_CARD]" in d2.sanitized_text
    assert "4111111111111111" not in d2.sanitized_text

    from audit import write_entry
    entry = write_entry({"tool_result": "card 4111111111111111"},
                        path=str(tmp_path / "a.jsonl"))
    assert "4111111111111111" not in json.dumps(entry)


# ---- 3. Username only: allowed ----
def test_username_only_is_allowed():
    action, types = classify_actions("username: john_doe92")
    assert action == "allow"
    # not redacted in output
    d = evaluate_output("Your username is set: username: john_doe92")
    assert d.decision == Decision.ALLOW


# ---- 4. External email with PII: block, log redacted ----
def test_external_email_with_pii_blocked_and_logged_redacted(tmp_path):
    fw = AgentShield(log=False)
    r = fw.inspect(
        user_input="please email my details externally",
        tool_call=ToolCall("send_email_dry_run",
                           {"to": "outsider@gmail.com",
                            "body": "SSN 123-45-6789, phone +6591234567"}),
        session_id="t")
    assert r.decision == Decision.BLOCK
    from audit import write_entry
    entry = write_entry(r.audit_dict(), path=str(tmp_path / "a.jsonl"))
    assert "123-45-6789" not in json.dumps(entry)


# ---- 5. API key / password in input: redacted in output and logs ----
def test_secret_in_input_redacted_everywhere(tmp_path):
    secret = "sk-live-9f8a7b6c5d4e3f2a1b0c"
    d = evaluate_output(f"Here is the key you asked for: {secret}")
    assert d.decision == Decision.SANITIZE
    assert secret not in d.sanitized_text
    assert "[REDACTED_SECRET]" in d.sanitized_text

    fw = AgentShield(log=False)
    r = fw.inspect(user_input=f"my key is {secret}", session_id="t",
                   user_request_summary=f"key {secret}")
    from audit import write_entry
    entry = write_entry(r.audit_dict(), path=str(tmp_path / "a.jsonl"))
    assert secret not in json.dumps(entry)
    assert "api_key" in entry["sensitive_types_detected"]


# ---- email masking behaviour ----
def test_email_is_masked_not_removed():
    assert mask_email("reach me at john@example.com") == "reach me at j***@example.com"
    cleaned, types = redact_sensitive_data("contact john@example.com")
    assert "j***@example.com" in cleaned
    assert "email_address" in types
